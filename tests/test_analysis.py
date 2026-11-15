"""
Unit tests for src/analysis.py

Run with:  python -m pytest tests/test_analysis.py -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from analysis import (
    analyze, redact_personal_data,
    _extract_domain, _is_punycode, _has_suspicious_tld,
    _is_url_shortener, _is_ip_url, _has_subdomain_brand_mismatch,
)


# ── Domain helpers ────────────────────────────────────────────────────────

class TestExtractDomain:
    def test_full_url(self):
        assert _extract_domain("https://www.example.com/path?q=1") == "example.com"

    def test_no_scheme(self):
        assert _extract_domain("example.com") == "example.com"

    def test_strips_www(self):
        assert _extract_domain("http://www.paypal.com") == "paypal.com"

    def test_ip_address(self):
        assert _extract_domain("http://192.168.1.1/phish") == "192.168.1.1"

    def test_empty(self):
        assert _extract_domain("") is None

    def test_garbage(self):
        # Should not raise
        result = _extract_domain("not a url at all !!!!")
        assert result is None or isinstance(result, str)


class TestPunycode:
    def test_plain_ascii(self):
        assert _is_punycode("example.com") is False

    def test_punycode_label(self):
        assert _is_punycode("xn--pple-43d.com") is True

    def test_mixed(self):
        assert _is_punycode("mail.xn--pple-43d.co.uk") is True


class TestSuspiciousTLD:
    def test_xyz(self):
        assert _has_suspicious_tld("evil.xyz") is True

    def test_top(self):
        assert _has_suspicious_tld("prize-claim.top") is True

    def test_safe(self):
        assert _has_suspicious_tld("gov.uk") is False

    def test_com(self):
        assert _has_suspicious_tld("example.com") is False


class TestURLShortener:
    def test_bitly(self):
        assert _is_url_shortener("bit.ly") is True

    def test_tinyurl(self):
        assert _is_url_shortener("tinyurl.com") is True

    def test_safe(self):
        assert _is_url_shortener("example.com") is False


class TestIPUrl:
    def test_ipv4(self):
        assert _is_ip_url("192.168.1.100") is True

    def test_domain(self):
        assert _is_ip_url("example.com") is False

    def test_partial(self):
        assert _is_ip_url("192.168") is False


class TestBrandMismatch:
    def test_paypal_in_subdomain(self):
        assert _has_subdomain_brand_mismatch("paypal.secure-update.com") is True

    def test_paypal_itself(self):
        assert _has_subdomain_brand_mismatch("paypal.com") is False

    def test_amazon_in_path_domain(self):
        assert _has_subdomain_brand_mismatch("amazon.suspicious.net") is True

    def test_no_brand(self):
        assert _has_subdomain_brand_mismatch("example.com") is False


# ── Full analysis ──────────────────────────────────────────────────────────

class TestAnalyze:

    # ── High-risk cases ──────────────────────────────────────────────────

    def test_phishing_url_shortener(self):
        result = analyze("https://bit.ly/abc123", kind="url")
        assert result.risk == "High"
        assert any("shortener" in s.lower() for s in result.signals)

    def test_punycode_domain(self):
        result = analyze("https://xn--pple-43d.com/login", kind="url")
        assert result.risk in ("High", "Medium")
        assert any("punycode" in s.lower() for s in result.signals)

    def test_suspicious_tld_xyz(self):
        result = analyze("http://claim-your-prize.xyz/now", kind="url")
        assert result.risk == "High"

    def test_brand_mismatch_subdomain(self):
        result = analyze("https://paypal.secure-verify-update.com/", kind="url")
        assert result.risk == "High"
        assert any("brand" in s.lower() or "impersonat" in s.lower() for s in result.signals)

    def test_ip_address_url(self):
        result = analyze("http://185.220.101.5/account/verify", kind="url")
        assert result.risk == "High"
        assert any("IP address" in s for s in result.signals)

    def test_urgent_message(self):
        result = analyze(
            "URGENT: Your account has been suspended. Verify immediately at http://bank-secure-login.xyz",
            kind="message",
        )
        assert result.risk == "High"
        assert any("urgency" in s.lower() or "urgent" in s.lower() for s in result.signals)

    def test_credential_request(self):
        result = analyze(
            "Please enter your password and credit card number to continue.",
            kind="message",
        )
        assert result.risk in ("High", "Medium")
        assert any("credential" in s.lower() or "password" in s.lower() or "sensitive" in s.lower() for s in result.signals)

    def test_payment_lure(self):
        result = analyze(
            "You have won a £500 gift card. Pay a small release fee to claim your reward.",
            kind="message",
        )
        assert result.risk == "High"
        assert any("fee" in s.lower() or "payment" in s.lower() or "prize" in s.lower() for s in result.signals)

    # ── Medium-risk cases ────────────────────────────────────────────────

    def test_contains_link_only(self):
        result = analyze("https://example.com/product", kind="url")
        # A plain URL with no other signals should be Low or Medium
        assert result.risk in ("Low", "Medium")

    def test_brand_mention_in_message(self):
        result = analyze(
            "Dear customer, your Netflix account needs attention.",
            kind="message",
        )
        # Brand mention alone is medium or higher
        assert result.risk in ("Medium", "High")

    # ── Low-risk / no-signal cases ───────────────────────────────────────

    def test_benign_message(self):
        result = analyze("See you at the meeting tomorrow!", kind="message")
        assert result.risk == "Low"
        assert len(result.signals) >= 1  # Always returns at least one signal

    def test_no_signals_message(self):
        result = analyze("Happy birthday! Hope you have a great day.", kind="message")
        assert result.risk == "Low"
        assert "does not confirm" in result.signals[0] or "No common" in result.signals[0]

    # ── Advice and disclaimer ────────────────────────────────────────────

    def test_high_risk_includes_advice(self):
        result = analyze("http://bit.ly/x", kind="url")
        assert "Do not click" in result.advice or "not" in result.advice.lower()

    def test_disclaimer_always_present(self):
        for input_val, kind in [
            ("https://example.com", "url"),
            ("Hello world", "message"),
            ("URGENT verify now https://bit.ly/abc", "message"),
        ]:
            result = analyze(input_val, kind=kind)
            assert "not opened" in result.disclaimer or "heuristic" in result.disclaimer

    def test_low_advice_mentions_official_channels(self):
        result = analyze("Plain text with nothing suspicious.", kind="message")
        assert "official" in result.advice.lower()

    # ── Score bounds ────────────────────────────────────────────────────

    def test_score_bounded_0_100(self):
        # Even a maximally suspicious URL should not exceed 100.
        result = analyze(
            "URGENT: http://bit.ly/xn--pple-43d.xyz/verify?password=abc&credit_card=1234",
            kind="url",
        )
        assert 0 <= result.score <= 100

    def test_benign_score_low(self):
        result = analyze("Plain text message.", kind="message")
        assert result.score < 20

    # ── Edge cases ───────────────────────────────────────────────────────

    def test_empty_string(self):
        result = analyze("", kind="message")
        assert result.risk == "Low"

    def test_very_long_safe_text(self):
        result = analyze("a " * 999, kind="message")
        assert result.risk == "Low"

    def test_url_with_query_params(self):
        result = analyze("https://example.com/?q=hello&ref=test", kind="url")
        assert isinstance(result.risk, str)

    def test_multiple_urls_in_message(self):
        msg = " ".join([f"http://example{i}.com" for i in range(4)])
        result = analyze(msg, kind="message")
        assert any("multiple" in s.lower() for s in result.signals)

    def test_mixed_case_urgency(self):
        result = analyze("YOUR ACCOUNT IS LOCKED. ACT NOW.", kind="message")
        assert result.risk in ("High", "Medium")


# ── Redaction ─────────────────────────────────────────────────────────────

class TestRedact:

    def test_email_redacted(self):
        out = redact_personal_data("Contact me at john.doe@example.com please.")
        assert "@" not in out
        assert "[email redacted]" in out

    def test_phone_redacted(self):
        out = redact_personal_data("Call me on 07700 900 123 anytime.")
        assert "07700" not in out
        assert "[number redacted]" in out

    def test_no_personal_data_unchanged(self):
        text = "SMS scam about a parcel delivery fee."
        assert redact_personal_data(text) == text

    def test_multiple_emails(self):
        text = "From a@b.com and c@d.org"
        out = redact_personal_data(text)
        assert out.count("[email redacted]") == 2

    def test_uk_mobile(self):
        out = redact_personal_data("+44 7700 900000 is the number")
        assert "7700 900000" not in out

    def test_does_not_redact_years(self):
        # Short digit sequences that look like years should not be redacted.
        text = "Report from 2024."
        out = redact_personal_data(text)
        assert "2024" in out
