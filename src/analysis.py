"""
ScamTrace analysis engine.

Heuristic-only URL and message screening.  No URLs are fetched, resolved,
or visited.  Results are advisory and must not be presented as a definitive
verdict.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# URL shorteners — just the hostnames we know about.
URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "goo.gl", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
    "lnkd.in", "dl.dropboxusercontent.com", "u.to",
})

# Minimum score threshold for each risk label.
# Using separate constants makes calibration clear and testable.
_HIGH_THRESHOLD = 40
_MED_THRESHOLD = 20

# TLDs associated with high abuse rates.
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    ".top", ".click", ".xyz", ".loan", ".win", ".gq", ".tk",
    ".cf", ".ml", ".ga", ".work", ".date", ".racing", ".stream",
    ".download", ".accountant", ".review", ".country",
})

# Well-known brands commonly impersonated in scams.
BRAND_NAMES: frozenset[str] = frozenset({
    "paypal", "amazon", "netflix", "apple", "google", "microsoft",
    "facebook", "instagram", "whatsapp", "fedex", "dhl", "ups",
    "usps", "royalmail", "hmrc", "irs", "medicare", "visa", "mastercard",
    "barclays", "hsbc", "lloyds", "natwest", "santander", "chase",
    "wellsfargo", "bankofamerica",
})

# Urgency trigger words.
URGENCY_PATTERN = re.compile(
    r"\b(urgent|immediately|right away|act now|expires?|deadline|"
    r"limited time|last chance|within 24 hours?|within 48 hours?|"
    r"suspended|locked|blocked|compromised|unauthorized|verify now|"
    r"confirm (your|details|identity|account)|click here now|"
    r"respond immediately|warning|alert|your account)\b",
    re.IGNORECASE,
)

# Payment and lure phrases.
PAYMENT_PATTERN = re.compile(
    r"\b(fee|payment|pay (a |the )?small|transfer|wire|bitcoin|crypto|"
    r"gift card|voucher|redelivery|customs charge|release fee|admin fee|"
    r"prize|winner|won|reward|claim (your|a|the)|refund|cashback|"
    r"lottery|inheritance|advance fee|investment|guaranteed return)\b",
    re.IGNORECASE,
)

# Credential / sensitive-info requests.
CREDENTIAL_PATTERN = re.compile(
    r"\b(password|passcode|pin|ssn|social security|date of birth|"
    r"credit card|debit card|card number|cvv|sort code|bank account|"
    r"routing number|login|sign in|verify identity)\b",
    re.IGNORECASE,
)

# Personal data patterns used for redaction.
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(?<!\w)\+?[0-9][\d ()\-]{7,}[0-9](?!\w)")


# ---------------------------------------------------------------------------
# Domain / URL helpers (no network calls)
# ---------------------------------------------------------------------------

def _extract_domain(raw: str) -> str | None:
    """Return hostname from a URL-like string without fetching it."""
    candidate = raw.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
        # Strip port and strip www. prefix for comparison purposes.
        return host.lower().lstrip("www.") if host else None
    except Exception:
        return None


def _is_punycode(domain: str) -> bool:
    """Return True if the domain uses punycode (xn--) encoding."""
    return any(label.startswith("xn--") for label in domain.split("."))


def _has_suspicious_tld(domain: str) -> bool:
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False


def _is_url_shortener(domain: str) -> bool:
    # Compare against full domain and also bare host without port.
    host = domain.split(":")[0]
    return host in URL_SHORTENERS


def _has_lookalike_chars(domain: str) -> bool:
    """
    Detect homoglyph / lookalike substitutions in the domain portion.
    Looks for mixed scripts or characters whose Unicode names suggest
    they resemble ASCII letters (e.g. Cyrillic 'а', Greek 'ο').
    This is a lightweight heuristic, not a full homoglyph database.
    """
    latin_range = range(0x0041, 0x007B)  # A-z
    for ch in domain:
        cp = ord(ch)
        if cp > 127:
            name = unicodedata.name(ch, "")
            # Flag characters described as "LATIN" but outside basic ASCII
            # or any confusable from Cyrillic / Greek blocks.
            block = cp >> 8
            if block in (0x04, 0x03):  # Cyrillic / Greek
                return True
            if "LATIN" in name and cp not in latin_range:
                return True
    return False


def _is_ip_url(domain: str) -> bool:
    """Return True if the domain is a raw IP address."""
    # Simple IPv4 check.
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))


def _has_subdomain_brand_mismatch(domain: str) -> bool:
    """
    Detect patterns like 'paypal.update-secure-login.com' where a brand
    name appears in a subdomain but the registrable domain is unrelated.
    """
    parts = domain.split(".")
    # Registrable domain = last two labels (naive but sufficient for MVP).
    registrable = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    registrable_root = parts[-2] if len(parts) >= 2 else domain
    for brand in BRAND_NAMES:
        if brand in domain and brand not in registrable_root:
            return True
    return False


def _has_excessive_subdomains(domain: str) -> bool:
    """Flag domains with an unusual number of subdomain labels."""
    return len(domain.split(".")) >= 5


def _has_long_random_subdomain(domain: str) -> bool:
    """Detect long, random-looking subdomain prefixes (entropy heuristic)."""
    labels = domain.split(".")
    if len(labels) < 3:
        return False
    subdomain = labels[0]
    if len(subdomain) < 12:
        return False
    # Count character-class variety; random strings tend to mix digits and letters.
    has_digits = any(c.isdigit() for c in subdomain)
    has_alpha = any(c.isalpha() for c in subdomain)
    has_hyphens = "-" in subdomain
    variety = sum([has_digits, has_alpha, has_hyphens])
    return len(subdomain) >= 16 or (len(subdomain) >= 12 and variety >= 2)


# ---------------------------------------------------------------------------
# Signal dataclass
# ---------------------------------------------------------------------------

@dataclass
class Signal:
    code: str        # machine-readable identifier
    text: str        # human-readable description
    weight: int      # relative risk contribution


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

class AnalysisResult(NamedTuple):
    risk: str            # "High" | "Medium" | "Low"
    score: int           # 0–100 approximate risk score
    signals: list[str]   # human-readable signal descriptions
    advice: str          # safety guidance
    disclaimer: str      # mandatory advisory notice


_DISCLAIMER = (
    "This is a heuristic screen — no link was opened or fetched. "
    "A low-risk result does not confirm safety. "
    "Always verify through the organization's official website or phone number, "
    "not through links or numbers in the message."
)


def analyze(value: str, kind: str = "url") -> AnalysisResult:
    """
    Analyze a URL or message text for scam risk signals.

    Parameters
    ----------
    value : str
        The URL or message text supplied by the user (max 2 000 chars).
    kind : str
        'url' or 'message'.

    Returns
    -------
    AnalysisResult
        Named tuple with risk label, score, signal list, advice, and disclaimer.
    """
    value = value.strip()
    lower = value.lower()
    detected: list[Signal] = []

    # ── URL-specific checks ──────────────────────────────────────────────
    if kind == "url" or "://" in value or re.search(r"\bhttps?://", value, re.I):
        domain = _extract_domain(value)
        if domain:
            detected.append(Signal("contains_url", "Contains a web link (not opened or fetched).", 5))

            if _is_url_shortener(domain):
                detected.append(Signal("shortener", "Uses a URL shortener — the final destination is hidden.", 40))

            if _is_punycode(domain):
                detected.append(Signal("punycode", "Domain uses punycode encoding — may be a homoglyph lookalike.", 30))

            if _has_lookalike_chars(domain):
                detected.append(Signal("homoglyph", "Domain contains non-ASCII lookalike characters — possible impersonation.", 35))

            if _is_ip_url(domain):
                detected.append(Signal("ip_url", "URL uses a raw IP address instead of a domain name.", 40))

            if _has_suspicious_tld(domain):
                detected.append(Signal("suspicious_tld", f"Domain ends with a TLD commonly associated with scam infrastructure.", 20))

            if _has_subdomain_brand_mismatch(domain):
                detected.append(Signal("brand_mismatch", "A brand name appears in the URL but the registrable domain is unrelated — a common impersonation pattern.", 35))

            if _has_excessive_subdomains(domain):
                detected.append(Signal("many_subdomains", "URL has an unusually large number of subdomain levels.", 15))

            if _has_long_random_subdomain(domain):
                detected.append(Signal("random_subdomain", "Subdomain appears long and randomly generated.", 15))

            # Keyword signals in the domain / path itself.
            if re.search(r"secure|verify|update|login|signin|account|validate|confirm", domain):
                detected.append(Signal("security_keywords_in_domain", "Security-sounding words appear in the domain.", 20))

    # ── Content-level checks ─────────────────────────────────────────────
    if URGENCY_PATTERN.search(lower):
        detected.append(Signal("urgency", "Contains urgency or account-pressure language.", 20))

    if PAYMENT_PATTERN.search(lower):
        # Count distinct match groups to gauge severity: advance-fee scams
        # often chain multiple lure terms together.
        matches = PAYMENT_PATTERN.findall(lower)
        unique = len(set(m[0].lower() if isinstance(m, tuple) else m.lower() for m in matches))
        weight = 45 if unique >= 4 else 30 if unique >= 2 else 20
        detected.append(Signal("payment_lure", "Mentions fees, payments, prizes, or refunds — common scam lures.", weight))

    if CREDENTIAL_PATTERN.search(lower):
        detected.append(Signal("credential_request", "Asks for credentials or sensitive personal information.", 30))

    # Brand impersonation in message text.
    for brand in BRAND_NAMES:
        if brand in lower:
            detected.append(Signal("impersonation_text", f"Mentions a recognizable brand name — verify the sender through the brand's official website.", 20))
            break

    # Suspicious link count in message.
    urls_in_text = re.findall(r"https?://\S+", value, re.I)
    if len(urls_in_text) >= 3:
        detected.append(Signal("many_urls", "Contains multiple links — unusual for legitimate messages.", 15))

    # ── Sensitive data warning ───────────────────────────────────────────
    if EMAIL_RE.search(value) or PHONE_RE.search(value):
        detected.append(Signal("sensitive_data", "The text may contain personal contact information — avoid submitting personal details.", 10))

    # ── Score and risk label ─────────────────────────────────────────────
    total_weight = sum(s.weight for s in detected)
    # Cap at 100 and bin into risk labels.
    score = min(total_weight, 100)
    if score >= _HIGH_THRESHOLD:
        risk = "High"
    elif score >= _MED_THRESHOLD:
        risk = "Medium"
    else:
        risk = "Low"

    if not detected:
        signal_texts = ["No common scam patterns detected in this text. This does not confirm it is safe."]
    else:
        signal_texts = [s.text for s in detected]

    # ── Advice ───────────────────────────────────────────────────────────
    if risk == "High":
        advice = (
            "Do not click any links, provide information, or make payments. "
            "Report suspicious messages to your bank or the relevant authority. "
            "If you think you may have been targeted, contact the organization directly "
            "using contact details from their official website."
        )
    elif risk == "Medium":
        advice = (
            "Treat this with caution. Verify the sender by contacting the organization "
            "through their official website or a phone number you look up independently. "
            "Do not use contact details provided in the message."
        )
    else:
        advice = (
            "No strong risk signals were found. "
            "Still verify the sender through official channels if anything feels off."
        )

    return AnalysisResult(
        risk=risk,
        score=score,
        signals=signal_texts,
        advice=advice,
        disclaimer=_DISCLAIMER,
    )


def redact_personal_data(text: str) -> str:
    """Remove common personal identifiers before storing a report."""
    text = EMAIL_RE.sub("[email redacted]", text)
    text = PHONE_RE.sub("[number redacted]", text)
    return text
