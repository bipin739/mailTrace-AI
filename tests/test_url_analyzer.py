import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.url_analyzer import URLAnalyzerService
from backend.services.email_parser import EmailParserService


@pytest.fixture
def analyzer():
    return URLAnalyzerService()


def test_normal_url(analyzer):
    res = analyzer.analyze_url("https://www.example.com/about/company")
    assert res.domain == "example.com"
    assert res.features.scheme == "https"
    assert res.features.hostname == "www.example.com"
    assert res.features.registered_domain == "example.com"
    assert res.features.subdomain == "www"
    assert res.features.subdomain_count == 1
    assert res.features.is_ip_host is False
    assert res.features.is_punycode is False
    assert res.features.has_credentials is False
    assert res.features.is_shortener is False
    assert res.features.has_non_standard_port is False
    assert res.features.display_link_mismatch is False
    assert res.suspicion_score == 0
    assert res.suspicion_level == "low"


def test_ip_url_ipv4(analyzer):
    res = analyzer.analyze_url("http://192.0.2.1/login")
    assert res.features.is_ip_host is True
    assert res.features.ip_version == 4
    assert res.features.hostname == "192.0.2.1"
    assert "login" in res.features.suspicious_keywords
    assert res.suspicion_score >= 25
    assert any("Direct IP address" in reason for reason in res.score_reasons)


def test_ip_url_ipv6(analyzer):
    res = analyzer.analyze_url("http://[2001:db8::1]:8080/index.html")
    assert res.features.is_ip_host is True
    assert res.features.ip_version == 6
    assert res.features.port == 8080
    assert res.features.has_non_standard_port is True
    assert any("Non-standard port" in reason for reason in res.score_reasons)


def test_punycode_url(analyzer):
    res = analyzer.analyze_url("https://xn--e1afmkfd.xn--p1ai/test")
    assert res.features.is_punycode is True
    assert any("Punycode" in reason for reason in res.score_reasons)
    assert res.suspicion_score >= 15


def test_long_url(analyzer):
    long_path = "a" * 160
    url = f"https://example.com/{long_path}"
    res = analyzer.analyze_url(url)
    assert res.features.total_length > 150
    assert any("long url" in reason.lower() for reason in res.score_reasons)


def test_shortener_url(analyzer):
    res = analyzer.analyze_url("https://bit.ly/3xyz123")
    assert res.features.is_shortener is True
    assert any("shortener" in reason.lower() for reason in res.score_reasons)
    assert res.suspicion_score >= 15


def test_display_link_mismatch(analyzer):
    res = analyzer.analyze_url(
        "http://evil.example/login",
        visible_text="https://microsoft.com"
    )
    assert res.features.display_link_mismatch is True
    assert res.features.visible_text_domain == "microsoft.com"
    assert any("HTML display link mismatch" in reason for reason in res.score_reasons)
    assert res.suspicion_score >= 35


def test_display_link_mismatch_same_domain(analyzer):
    res = analyzer.analyze_url(
        "https://microsoft.com/en-us/docs",
        visible_text="https://microsoft.com/docs"
    )
    assert res.features.display_link_mismatch is False


def test_encoded_path(analyzer):
    res = analyzer.analyze_url("https://example.com/%2e%2e%2f%6c%6f%67%69%6e")
    assert res.features.has_percent_encoding is True
    assert res.features.percent_encoding_count >= 3
    assert any("percent-encoded" in reason.lower() for reason in res.score_reasons)


def test_credentials_in_url(analyzer):
    res = analyzer.analyze_url("http://user:password@malicious-site.com/auth")
    assert res.features.has_credentials is True
    assert res.features.hostname == "malicious-site.com"
    assert any("credentials" in reason.lower() for reason in res.score_reasons)
    assert res.suspicion_score >= 25


def test_suspicious_keywords(analyzer):
    res = analyzer.analyze_url("https://example.org/account/verify/login/update/payment")
    assert "account" in res.features.suspicious_keywords
    assert "verify" in res.features.suspicious_keywords
    assert "login" in res.features.suspicious_keywords
    assert "update" in res.features.suspicious_keywords
    assert "payment" in res.features.suspicious_keywords


def test_lookalike_integration(analyzer):
    res = analyzer.analyze_url("http://micros0ft-login.com/auth")
    assert res.features.lookalike is not None
    assert res.features.lookalike.suspected_brand == "microsoft.com"
    assert any("Lookalike" in reason for reason in res.score_reasons)


def test_api_analyze_url_endpoint():
    client = TestClient(app)
    payload = {
        "url": "http://evil.example/auth",
        "visible_text": "https://paypal.com"
    }
    response = client.post("/api/emails/analyze-url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "http://evil.example/auth"
    assert data["features"]["display_link_mismatch"] is True
    assert data["features"]["visible_text_domain"] == "paypal.com"
    assert data["suspicion_score"] >= 35


def test_email_parsing_with_html_link_mismatch():
    raw_eml = (
        b"From: sender@example.com\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Security Update\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body>Please verify your account: "
        b"<a href=\"http://evil.example/login\">https://microsoft.com</a>"
        b"</body></html>"
    )
    analysis = EmailParserService.parse_eml_bytes(raw_eml, "phish.eml")
    assert len(analysis.url_analysis) > 0
    mismatch_url = next((u for u in analysis.url_analysis if u.url == "http://evil.example/login"), None)
    assert mismatch_url is not None
    assert mismatch_url.features.display_link_mismatch is True
    assert mismatch_url.features.visible_text_domain == "microsoft.com"
    assert mismatch_url.suspicion_score >= 35
