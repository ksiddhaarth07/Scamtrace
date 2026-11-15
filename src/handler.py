"""
ScamTrace Lambda handler.

Routes:
  POST /analyze   — heuristic URL / message screening (no URL fetch)
  POST /reports   — private community report submission
  GET  /signals   — curated public indicator feed (paginated)
  GET  /moderate  — moderator: list pending reports  [requires mod token]
  POST /moderate  — moderator: take action on report [requires mod token]

Data protection notes:
- Common emails and phone-like strings are redacted before DynamoDB storage.
- Raw report descriptions never appear in GET /signals responses.
- DynamoDB partition key uses a hash of the report UUID so the report ID
  is not derivable from the DynamoDB key.
- Moderator token is supplied via MODERATOR_TOKEN environment variable and
  compared with constant-time comparison to prevent timing attacks.
- All Lambda logs omit user-submitted content and personal identifiers.
"""

from __future__ import annotations

import decimal
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

from analysis import analyze, redact_personal_data

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TABLE_NAME = os.environ.get("TABLE_NAME", "")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*")
MODERATOR_TOKEN = os.environ.get("MODERATOR_TOKEN", "")

ddb = boto3.resource("dynamodb") if TABLE_NAME else None
table = ddb.Table(TABLE_NAME) if ddb else None

def get_table():
    global table, ddb, TABLE_NAME
    curr_table_name = os.environ.get("TABLE_NAME", TABLE_NAME)
    if table is None and curr_table_name:
        ddb = boto3.resource("dynamodb")
        table = ddb.Table(curr_table_name)
    return table

def get_moderator_token():
    return os.environ.get("MODERATOR_TOKEN", MODERATOR_TOKEN)

REPORT_TTL_DAYS = 90
MAX_INPUT_LENGTH = 2000
MAX_REPORT_LENGTH = 1000
MAX_PAGE_SIZE = 50
DEFAULT_PAGE_SIZE = 25

ALLOWED_CATEGORIES = frozenset({
    "Phishing URL",
    "SMS / text message",
    "Email scam",
    "Impersonation",
    "Payment fraud",
})

# ---------------------------------------------------------------------------
# Synthetic seed indicators (clearly labelled as synthetic sample data)
# ---------------------------------------------------------------------------

SEED_INDICATORS = [
    {
        "id": "sample-001",
        "indicator": "secure-parcel-track.example",
        "type": "URL",
        "risk": "High",
        "confidence": "Sample",
        "source": "Synthetic demo data",
        "firstSeen": "2026-11-01",
        "lastSeen": "2026-11-14",
        "reportCount": 38,
        "reviewStatus": "Sample — not a real threat record",
        "summary": "Fake parcel tracking domain used in SMS delivery lure campaigns.",
    },
    {
        "id": "sample-002",
        "indicator": '"Account locked" bank impersonation SMS',
        "type": "SMS pattern",
        "risk": "High",
        "confidence": "Sample",
        "source": "Synthetic demo data",
        "firstSeen": "2026-11-08",
        "lastSeen": "2026-11-14",
        "reportCount": 24,
        "reviewStatus": "Sample — not a real threat record",
        "summary": "Template SMS claiming the recipient's online banking is locked.",
    },
    {
        "id": "sample-003",
        "indicator": "claim-reward-2026.example",
        "type": "URL",
        "risk": "High",
        "confidence": "Sample",
        "source": "Synthetic demo data",
        "firstSeen": "2026-11-10",
        "lastSeen": "2026-11-13",
        "reportCount": 19,
        "reviewStatus": "Sample — not a real threat record",
        "summary": "Prize claim domain with .example TLD used in email campaigns.",
    },
    {
        "id": "sample-004",
        "indicator": "QuickLoan Pro brand impersonation",
        "type": "Impersonation",
        "risk": "Medium",
        "confidence": "Sample",
        "source": "Synthetic demo data",
        "firstSeen": "2026-11-11",
        "lastSeen": "2026-11-13",
        "reportCount": 12,
        "reviewStatus": "Sample — not a real threat record",
        "summary": "Fabricated lender brand used to solicit upfront fees.",
    },
    {
        "id": "sample-005",
        "indicator": '"Package held — pay redelivery fee" email',
        "type": "Email pattern",
        "risk": "Medium",
        "confidence": "Sample",
        "source": "Synthetic demo data",
        "firstSeen": "2026-11-09",
        "lastSeen": "2026-11-12",
        "reportCount": 9,
        "reviewStatus": "Sample — not a real threat record",
        "summary": "Delivery-lure email pattern requesting a small redelivery fee via link.",
    },
    {
        "id": "sample-006",
        "indicator": "Crypto recovery advance fee scheme",
        "type": "Payment fraud",
        "risk": "High",
        "confidence": "Sample",
        "source": "Synthetic demo data",
        "firstSeen": "2026-11-07",
        "lastSeen": "2026-11-11",
        "reportCount": 7,
        "reviewStatus": "Sample — not a real threat record",
        "summary": "Advance fee fraud claiming to recover lost cryptocurrency investments.",
    },
    {
        "id": "sample-007",
        "indicator": "marketplace-payment-help.example",
        "type": "URL",
        "risk": "Medium",
        "confidence": "Sample",
        "source": "Synthetic demo data",
        "firstSeen": "2026-11-08",
        "lastSeen": "2026-11-10",
        "reportCount": 5,
        "reviewStatus": "Sample — not a real threat record",
        "summary": "Domain mimicking a marketplace payment portal to redirect buyers.",
    },
    {
        "id": "sample-008",
        "indicator": '"Your refund is ready" phishing SMS',
        "type": "SMS pattern",
        "risk": "Low",
        "confidence": "Sample",
        "source": "Synthetic demo data",
        "firstSeen": "2026-11-06",
        "lastSeen": "2026-11-09",
        "reportCount": 3,
        "reviewStatus": "Sample — not a real threat record",
        "summary": "Tax refund lure SMS with link to credential-harvesting page.",
    },
]


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _cors_headers() -> dict[str, str]:
    return {
        "content-type": "application/json; charset=utf-8",
        "access-control-allow-origin": CORS_ORIGIN,
        "access-control-allow-headers": "content-type, x-mod-token",
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "cache-control": "no-store, no-cache",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }


def _json_default(obj):
    if isinstance(obj, decimal.Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


def _response(status: int, body: Any) -> dict:
    return {
        "statusCode": status,
        "headers": _cors_headers(),
        "body": json.dumps(body, ensure_ascii=False, default=_json_default),
    }


def _bad(message: str) -> dict:
    return _response(400, {"error": message})


def _not_found() -> dict:
    return _response(404, {"error": "Not found."})


def _server_error(request_id: str) -> dict:
    # Log a non-sensitive correlation token so support can cross-reference
    # CloudWatch logs without exposing personal data.
    ref = hashlib.sha256(request_id.encode()).hexdigest()[:12]
    print(f"error ref={ref}")
    return _response(500, {"error": "Service temporarily unavailable.", "ref": ref})


def _constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to resist timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

def _handle_analyze(body: dict) -> dict:
    value = str(body.get("input", "")).strip()
    kind = str(body.get("kind", "url")).lower()
    if kind not in ("url", "message"):
        return _bad("kind must be 'url' or 'message'.")
    if not value:
        return _bad("Provide a URL or message to analyze.")
    if len(value) > MAX_INPUT_LENGTH:
        return _bad(f"Input must be {MAX_INPUT_LENGTH} characters or fewer.")
    result = analyze(value, kind)
    return _response(200, {
        "risk": result.risk,
        "score": result.score,
        "signals": result.signals,
        "advice": result.advice,
        "disclaimer": result.disclaimer,
        "source": "local-heuristic",
    })


def _handle_submit_report(body: dict) -> dict:
    description = str(body.get("description", "")).strip()
    category = str(body.get("category", ""))
    if category not in ALLOWED_CATEGORIES:
        return _bad("Choose a valid category.")
    if not description:
        return _bad("Description is required.")
    if len(description) > MAX_REPORT_LENGTH:
        return _bad(f"Description must be {MAX_REPORT_LENGTH} characters or fewer.")

    # Redact common personal identifiers before any storage.
    safe_description = redact_personal_data(description)

    tbl = get_table()
    if not tbl:
        return _response(503, {"error": "Report storage is not configured for this deployment."})

    report_id = str(uuid.uuid4())
    # Store under a hashed key so raw UUIDs are not in the partition key space.
    pk = "REPORT#" + hashlib.sha256(report_id.encode()).hexdigest()[:32]
    now = int(time.time())

    tbl.put_item(Item={
        "pk": pk,
        "sk": "v0",
        "referenceId": report_id,
        "category": category,
        "description": safe_description,
        "createdAt": now,
        "ttl": now + REPORT_TTL_DAYS * 86400,
        "status": "PENDING_REVIEW",
    })

    return _response(201, {
        "received": True,
        "reference": report_id,
        "message": (
            "Report received. It is stored privately and excluded from the public feed "
            "until a moderator reviews it. It will be automatically deleted after "
            f"{REPORT_TTL_DAYS} days."
        ),
    })


def _handle_signals(params: dict) -> dict:
    """
    Public indicator feed.  Returns synthetic seed data with clear labelling.
    When a live DynamoDB table is configured, promoted records are merged in.
    Raw report text is never included.
    """
    # Parse pagination / filter params.
    try:
        page_size = min(max(int(params.get("pageSize", DEFAULT_PAGE_SIZE)), 1), MAX_PAGE_SIZE)
        page = max(0, int(params.get("page", 0)))
    except (ValueError, TypeError):
        return _bad("pageSize and page must be integers.")

    risk_filter = params.get("risk", "").strip()
    search = params.get("q", "").strip().lower()

    items = list(SEED_INDICATORS)

    tbl = get_table()
    if tbl:
        try:
            query_args = {
                "IndexName": "StatusIndex",
                "KeyConditionExpression": Key("status").eq("PROMOTED"),
            }
            while True:
                resp = tbl.query(**query_args)
                for rec in resp.get("Items", []):
                    items.append({
                        "id": rec.get("referenceId", ""),
                        "indicator": rec.get("indicator", ""),
                        "type": rec.get("indicatorType", ""),
                        "risk": rec.get("risk", ""),
                        "confidence": "Community-reviewed",
                        "source": "Community report — reviewed",
                        "firstSeen": rec.get("firstSeen", ""),
                        "lastSeen": rec.get("lastSeen", ""),
                        "reportCount": rec.get("reportCount", 1),
                        "reviewStatus": "Reviewed",
                        "summary": "Moderator-reviewed community indicator.",
                    })
                last_key = resp.get("LastEvaluatedKey")
                if not last_key:
                    break
                query_args["ExclusiveStartKey"] = last_key
        except Exception:
            # Non-fatal: seed data is still returned.
            pass

    # Apply filters.
    if risk_filter and risk_filter in ("High", "Medium", "Low"):
        items = [i for i in items if i.get("risk") == risk_filter]
    if search:
        items = [
            i for i in items
            if search in i.get("indicator", "").lower()
            or search in i.get("type", "").lower()
            or search in i.get("summary", "").lower()
        ]

    total = len(items)
    start = page * page_size
    page_items = items[start:start + page_size]

    return _response(200, {
        "items": page_items,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "hasMore": start + page_size < total,
        "notice": "Sample data shown. These indicators are synthetic and not real threat intelligence.",
    })


def _handle_moderate_get(headers: dict, params: dict) -> dict:
    """List pending reports for the moderation interface."""
    token = headers.get("x-mod-token", "")
    expected_token = get_moderator_token()
    if not expected_token or not token or not _constant_time_compare(token, expected_token):
        return _response(401, {"error": "Unauthorized."})
    tbl = get_table()
    if not tbl:
        return _response(503, {"error": "Storage not configured."})

    try:
        resp = tbl.query(
            IndexName="StatusIndex",
            KeyConditionExpression=Key("status").eq("PENDING_REVIEW"),
            ProjectionExpression="pk, referenceId, category, description, createdAt, #st",
            ExpressionAttributeNames={"#st": "status"},
            Limit=50,
        )
    except Exception:
        return _response(503, {"error": "Could not list reports."})

    reports = []
    for item in resp.get("Items", []):
        reports.append({
            "pk": item.get("pk"),
            "referenceId": item.get("referenceId"),
            "category": item.get("category"),
            "description": item.get("description", ""),
            "createdAt": item.get("createdAt"),
            "status": item.get("status"),
        })

    return _response(200, {"reports": reports, "count": len(reports)})


def _handle_moderate_post(headers: dict, body: dict) -> dict:
    """Take a moderation action on a report."""
    token = headers.get("x-mod-token", "")
    expected_token = get_moderator_token()
    if not expected_token or not token or not _constant_time_compare(token, expected_token):
        return _response(401, {"error": "Unauthorized."})
    tbl = get_table()
    if not tbl:
        return _response(503, {"error": "Storage not configured."})

    pk = str(body.get("pk", "")).strip()
    action = str(body.get("action", "")).strip()

    if not pk or action not in ("approve", "dismiss", "promote"):
        return _bad("Provide pk and action (approve | dismiss | promote).")

    if action == "dismiss":
        new_status = "DISMISSED"
    elif action == "approve":
        new_status = "REVIEWED"
    else:  # promote
        new_status = "PROMOTED"
        # For promotion, require additional indicator fields.
        indicator = str(body.get("indicator", "")).strip()
        indicator_type = str(body.get("indicatorType", "")).strip()
        risk = str(body.get("risk", "")).strip()
        if not indicator or indicator_type not in ("URL", "SMS pattern", "Email pattern", "Impersonation", "Payment fraud") or risk not in ("High", "Medium", "Low"):
            return _bad("Promotion requires indicator, indicatorType, and risk.")

    try:
        update_expr = "SET #st = :s, reviewedAt = :t"
        expr_names = {"#st": "status"}
        expr_values: dict = {":s": new_status, ":t": int(time.time())}

        if action == "promote":
            update_expr += ", #ind = :ind, indicatorType = :it, #rk = :rk"
            expr_names["#rk"] = "risk"
            expr_names["#ind"] = "indicator"
            expr_values[":ind"] = indicator
            expr_values[":it"] = indicator_type
            expr_values[":rk"] = risk
            expr_values[":confidence"] = "Community-reviewed"
            expr_values[":first"] = time.strftime("%Y-%m-%d", time.gmtime())
            expr_values[":last"] = time.strftime("%Y-%m-%d", time.gmtime())
            expr_values[":count"] = 1
            update_expr += ", confidence = :confidence, firstSeen = :first, lastSeen = :last, reportCount = :count"

        expr_names["#current"] = "status"
        expr_values[":pending"] = "PENDING_REVIEW"

        tbl.update_item(
            Key={"pk": pk, "sk": "v0"},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
            ConditionExpression="attribute_exists(pk) AND #current = :pending",
        )
    except Exception:
        return _response(503, {"error": "Could not update report."})

    return _response(200, {"updated": True, "newStatus": new_status})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def handler(event: dict, context: Any) -> dict:
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET").upper()
    path = event.get("rawPath", "/")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    params = event.get("queryStringParameters") or {}

    if method == "OPTIONS":
        return _response(204, {})

    try:
        body: dict = {}
        if method == "POST":
            raw_body = event.get("body") or "{}"
            body = json.loads(raw_body)
            if not isinstance(body, dict):
                return _bad("Request body must be a JSON object.")

        if method == "POST" and path.endswith("/analyze"):
            return _handle_analyze(body)

        if method == "POST" and path.endswith("/reports"):
            return _handle_submit_report(body)

        if method == "GET" and path.endswith("/signals"):
            return _handle_signals(params)

        if method == "GET" and path.endswith("/moderate"):
            return _handle_moderate_get(headers, params)

        if method == "POST" and path.endswith("/moderate"):
            return _handle_moderate_post(headers, body)

        return _not_found()

    except (json.JSONDecodeError, ValueError, TypeError):
        return _bad("Invalid or malformed request body.")
    except Exception:
        req_id = getattr(context, "aws_request_id", "unknown")
        return _server_error(req_id)
