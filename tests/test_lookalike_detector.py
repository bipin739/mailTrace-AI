import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.brand_config import BrandConfigService, BrandInfo
from backend.services.lookalike_detector import LookalikeDetectorService


client = TestClient(app)


@pytest.fixture
def detector_service():
    return LookalikeDetectorService()


def test_exact_brand_domain_false_positive_control(detector_service):
    """Exact brand domains must NEVER be flagged as impersonating themselves."""
    for domain in ["microsoft.com", "google.com", "apple.com", "amazon.com", "paypal.com"]:
        res = detector_service.detect_lookalike(domain)
        assert res is None, f"False positive: {domain} should not be flagged as a lookalike"


def test_official_brand_subdomain_false_positive_control(detector_service):
    """Legitimate subdomains of official brands must NEVER be flagged."""
    legit_subdomains = [
        "login.microsoft.com",
        "account.microsoft.com",
        "mail.google.com",
        "accounts.google.com",
        "auth.paypal.com",
        "api.github.com",
        "id.apple.com"
    ]
    for domain in legit_subdomains:
        res = detector_service.detect_lookalike(domain)
        assert res is None, f"False positive: official subdomain {domain} should not be flagged"


def test_unrelated_domains_not_flagged(detector_service):
    """Unrelated benign domains must not trigger false positives."""
    unrelated = [
        "example.com",
        "randomcompany.org",
        "weather.com",
        "wikipedia.org",
        "theguardian.co.uk",
        "nationalpost.ca"
    ]
    for domain in unrelated:
        res = detector_service.detect_lookalike(domain)
        assert res is None, f"False positive: unrelated domain {domain} was flagged"


def test_digit_substitution(detector_service):
    """Detects 0->o, 1->l/i digit/leet substitution."""
    # micros0ft.com -> microsoft.com
    res1 = detector_service.detect_lookalike("micros0ft.com")
    assert res1 is not None
    assert res1.suspected_brand == "microsoft.com"
    assert res1.brand_name == "Microsoft"
    assert "character_substitution" in res1.techniques
    assert res1.similarity >= 0.90
    assert res1.confidence_label == "Potential brand impersonation"

    # paypa1.com -> paypal.com
    res2 = detector_service.detect_lookalike("paypa1.com")
    assert res2 is not None
    assert res2.suspected_brand == "paypal.com"
    assert res2.brand_name == "PayPal"
    assert "character_substitution" in res2.techniques
    assert res2.similarity >= 0.90


def test_hyphen_variation(detector_service):
    """Detects extra hyphens inserted into brand names."""
    # micro-soft.com -> microsoft.com
    res1 = detector_service.detect_lookalike("micro-soft.com")
    assert res1 is not None
    assert res1.suspected_brand == "microsoft.com"
    assert "hyphenation" in res1.techniques
    assert res1.similarity >= 0.88

    # pay-pal.com -> paypal.com
    res2 = detector_service.detect_lookalike("pay-pal.com")
    assert res2 is not None
    assert res2.suspected_brand == "paypal.com"
    assert "hyphenation" in res2.techniques


def test_added_affixes_and_brand_keyword(detector_service):
    """Detects brand keywords coupled with deceptive security/login affixes."""
    # micros0ft-login.com
    res = detector_service.detect_lookalike("micros0ft-login.com")
    assert res is not None
    assert res.suspected_brand == "microsoft.com"
    assert res.brand_name == "Microsoft"
    assert res.similarity == 0.91
    assert "character_substitution" in res.techniques
    assert "brand_keyword" in res.techniques
    assert res.confidence_label == "Potential brand impersonation"


def test_suspicious_subdomain_abuse(detector_service):
    """
    Detects brand keyword in subdomain when registered domain is a foreign 3rd party.
    e.g. login.microsoft.example.com -> registered domain is example.com, NOT microsoft.com.
    """
    res = detector_service.detect_lookalike("login.microsoft.example.com")
    assert res is not None
    assert res.suspected_brand == "microsoft.com"
    assert res.brand_name == "Microsoft"
    assert "suspicious_subdomain_abuse" in res.techniques
    assert "brand_keyword" in res.techniques
    assert res.similarity >= 0.90
    assert "example.com" in res.details


def test_punycode_and_homoglyphs(detector_service):
    """Detects Punycode and Unicode visual homoglyphs mimicking brands."""
    # Punycode representation of microsóft or Cyrillic homoglyphs
    res1 = detector_service.detect_lookalike("xn--microsft-03a.com")
    assert res1 is not None
    assert res1.suspected_brand == "microsoft.com"
    assert "punycode" in res1.techniques or "unicode_homoglyphs" in res1.techniques

    # Direct Cyrillic 'о' in google: g\u043e\u043egle.com
    cyrillic_google = "g\u043e\u043egle.com"
    res2 = detector_service.detect_lookalike(cyrillic_google)
    assert res2 is not None
    assert res2.suspected_brand == "google.com"
    assert "unicode_homoglyphs" in res2.techniques


def test_custom_configurable_brand():
    """Verifies that brands are dynamically configurable without changing service code."""
    custom_config = BrandConfigService(initial_brands=[
        BrandInfo(name="CustomBank", domain="custombank.com", base_name="custombank", keywords=["custombank"])
    ])
    custom_detector = LookalikeDetectorService(brand_config=custom_config)

    # Legitimate brand domain
    assert custom_detector.detect_lookalike("custombank.com") is None
    assert custom_detector.detect_lookalike("online.custombank.com") is None

    # Lookalike with leet substitution
    res = custom_detector.detect_lookalike("cust0mbank-login.com")
    assert res is not None
    assert res.suspected_brand == "custombank.com"
    assert res.brand_name == "CustomBank"
    assert "character_substitution" in res.techniques


def test_api_detect_lookalike_endpoint():
    """Verifies FastAPI GET /api/emails/detect-lookalike/{domain} endpoint."""
    response = client.get("/api/emails/detect-lookalike/micros0ft-login.com")
    assert response.status_code == 200
    data = response.json()

    assert data is not None
    assert data["domain"] == "micros0ft-login.com"
    assert data["suspected_brand"] == "microsoft.com"
    assert data["brand_name"] == "Microsoft"
    assert data["similarity"] == 0.91
    assert "character_substitution" in data["techniques"]
    assert "brand_keyword" in data["techniques"]
    assert data["confidence_label"] == "Potential brand impersonation"


def test_api_detect_lookalike_endpoint_clean_domain():
    """Verifies endpoint returns null for authentic or unrelated domains."""
    response = client.get("/api/emails/detect-lookalike/microsoft.com")
    assert response.status_code == 200
    assert response.json() is None

    response2 = client.get("/api/emails/detect-lookalike/example.com")
    assert response2.status_code == 200
    assert response2.json() is None
