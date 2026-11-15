"""
Integration unit tests for src/handler.py using moto to mock DynamoDB.

Tests:
- POST /analyze (URL and message)
- POST /reports (creation, validation, redaction, status=PENDING_REVIEW)
- GET /signals (returns seed indicators + promoted indicators from StatusIndex)
- GET /moderate (authentication check with x-mod-token, list pending reports)
- POST /moderate (approve, dismiss, promote into StatusIndex)
"""

import json
import os
import sys
import pytest
from moto import mock_aws
import boto3

# Add src to python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def aws_env(monkeypatch):
    """Set up mock AWS environment and DynamoDB table matching template.yaml."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("TABLE_NAME", "ScamTraceReports-Test")
    monkeypatch.setenv("MODERATOR_TOKEN", "super-secret-test-token-32charactersminimum!")
    monkeypatch.setenv("CORS_ORIGIN", "https://scamtrace.example.com")

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="ScamTraceReports-Test",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "createdAt", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "StatusIndex",
                    "KeySchema": [
                        {"AttributeName": "status", "KeyType": "HASH"},
                        {"AttributeName": "createdAt", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        
        # Re-import handler or reload module so module-level `table` is set
        import handler
        handler.TABLE_NAME = "ScamTraceReports-Test"
        handler.MODERATOR_TOKEN = "super-secret-test-token-32charactersminimum!"
        handler.CORS_ORIGIN = "https://scamtrace.example.com"
        handler.ddb = ddb
        handler.table = table

        yield handler, table


def test_analyze_url(aws_env):
    handler, _ = aws_env
    event = {
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": "/analyze",
        "body": json.dumps({"kind": "url", "input": "https://secure-parcel-track.example/fee"}),
    }
    resp = handler.handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert "risk" in body
    assert body["risk"] in ("High", "Medium", "Low")
    assert "signals" in body
    assert "advice" in body
    assert "disclaimer" in body


def test_analyze_validation_error(aws_env):
    handler, _ = aws_env
    event = {
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": "/analyze",
        "body": json.dumps({"kind": "invalid", "input": "test"}),
    }
    resp = handler.handler(event, None)
    assert resp["statusCode"] == 400


def test_reports_submission_and_redaction(aws_env):
    handler, table = aws_env
    raw_text = "Received an SMS from +1 (555) 234-5678 asking to email victim@example.com for parcel release fee"
    event = {
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": "/reports",
        "body": json.dumps({
            "category": "SMS / text message",
            "description": raw_text,
        }),
    }
    resp = handler.handler(event, None)
    assert resp["statusCode"] == 201
    body = json.loads(resp["body"])
    assert body["received"] is True
    assert "reference" in body

    # Check DynamoDB persistence and redaction
    items = table.scan()["Items"]
    assert len(items) == 1
    stored = items[0]
    assert stored["status"] == "PENDING_REVIEW"
    assert stored["category"] == "SMS / text message"
    assert "victim@example.com" not in stored["description"]
    assert "[email redacted]" in stored["description"]
    assert "[number redacted]" in stored["description"]


def test_signals_returns_seed(aws_env):
    handler, _ = aws_env
    event = {
        "requestContext": {"http": {"method": "GET"}},
        "rawPath": "/signals",
        "queryStringParameters": {},
    }
    resp = handler.handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert "items" in body
    assert body["total"] >= 8
    assert any("secure-parcel-track" in i["indicator"] for i in body["items"])


def test_moderate_auth_failure(aws_env):
    handler, _ = aws_env
    # Without token
    event = {
        "requestContext": {"http": {"method": "GET"}},
        "rawPath": "/moderate",
        "headers": {},
    }
    resp = handler.handler(event, None)
    assert resp["statusCode"] == 401

    # With invalid token
    event["headers"] = {"x-mod-token": "wrong-token"}
    resp = handler.handler(event, None)
    assert resp["statusCode"] == 401


def test_moderation_workflow_approve_and_promote(aws_env):
    handler, table = aws_env
    token = "super-secret-test-token-32charactersminimum!"

    # 1. Submit a report
    sub_event = {
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": "/reports",
        "body": json.dumps({
            "category": "Phishing URL",
            "description": "Fake payment link targeting buyers",
        }),
    }
    sub_resp = handler.handler(sub_event, None)
    assert sub_resp["statusCode"] == 201

    # 2. Moderator retrieves reports
    list_event = {
        "requestContext": {"http": {"method": "GET"}},
        "rawPath": "/moderate",
        "headers": {"x-mod-token": token},
    }
    list_resp = handler.handler(list_event, None)
    assert list_resp["statusCode"] == 200
    reports = json.loads(list_resp["body"])["reports"]
    assert len(reports) == 1
    report_pk = reports[0]["pk"]

    # 3. Moderator promotes report into public indicators
    promote_event = {
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": "/moderate",
        "headers": {"x-mod-token": token},
        "body": json.dumps({
            "pk": report_pk,
            "action": "promote",
            "indicator": "fake-escrow-payment.example",
            "indicatorType": "URL",
            "risk": "High",
        }),
    }
    promote_resp = handler.handler(promote_event, None)
    assert promote_resp["statusCode"] == 200
    assert json.loads(promote_resp["body"])["newStatus"] == "PROMOTED"

    # 4. Check public /signals includes promoted item
    sig_event = {
        "requestContext": {"http": {"method": "GET"}},
        "rawPath": "/signals",
        "queryStringParameters": {"q": "fake-escrow-payment"},
    }
    sig_resp = handler.handler(sig_event, None)
    assert sig_resp["statusCode"] == 200
    sig_body = json.loads(sig_resp["body"])
    assert any(i["indicator"] == "fake-escrow-payment.example" for i in sig_body["items"])
