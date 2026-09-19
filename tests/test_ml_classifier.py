import io
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.app.ml.normalizer import TextNormalizer
from backend.app.ml.classifier import PhishingClassifier, global_phishing_classifier
from backend.schemas.email import EmailAnalysisResponse, MLAssessmentResult
from backend.services.threat_scorer import ThreatScorerService

client = TestClient(app)


# =====================================================================
# 1. TextNormalizer Unit Tests
# =====================================================================

def test_text_normalizer_basic():
    subject = "URGENT: Verify Your Account Password"
    body = "Click http://evil.com/login to update your account now."
    normalized = TextNormalizer.normalize(subject, body)

    assert "httpurl" in normalized
    assert "urgent" in normalized
    assert "password" in normalized
    assert "URGENT" not in normalized  # Lowercased


def test_text_normalizer_tokens():
    text = "Contact support@bank.com at 192.168.1.10 or call 18005551234. Fee is $250.00."
    normalized = TextNormalizer.normalize(body=text)

    assert "emailaddr" in normalized
    assert "ipaddr" in normalized
    assert "moneysym" in normalized
    assert "numtoken" in normalized


def test_text_normalizer_empty_and_none():
    assert TextNormalizer.normalize(None, None) == ""
    assert TextNormalizer.normalize("", "") == ""
    assert TextNormalizer.normalize("   ", "   \n\t  ") == ""
    assert TextNormalizer.normalize("Only Subject", None) == "only subject"
    assert TextNormalizer.normalize(None, "Only Body") == "only body"


def test_text_normalizer_non_english_unicode():
    # Accented Latin, Cyrillic, Chinese, Arabic, and emojis
    multilingual = "Café crème brûlée! Срочно обновите пароль: 紧急通知 请确认密码! تنبيه أمني عاجل ⚠️🚨"
    normalized = TextNormalizer.normalize(subject="International Alert", body=multilingual)

    assert isinstance(normalized, str)
    assert len(normalized) > 0
    assert "international alert" in normalized
    assert "cafe" in normalized  # NFKD normalized accents


# =====================================================================
# 2. PhishingClassifier Interface & Fallback Tests
# =====================================================================

def test_phishing_classifier_prediction_phishing():
    subject = "Action Required: Microsoft 365 Password Expiration Notice"
    body = "Your password expires today. Please verify your credentials at http://microsoft-verify-login.com to avoid account suspension."
    result = global_phishing_classifier.predict(subject, body)

    assert result["classification"] in ("phishing", "legitimate")
    assert isinstance(result["probability"], float)
    assert 0.0 <= result["probability"] <= 1.0
    assert result["available"] is True
    assert "TF-IDF + Logistic Regression" in result["model_name"]
    assert isinstance(result["top_features"], list)


def test_phishing_classifier_prediction_legitimate():
    subject = "Weekly Engineering Sync Notes"
    body = "Hi team, thanks for joining today's sprint sync. The frontend redesign is on track for QA on Thursday. Have a great weekend!"
    result = global_phishing_classifier.predict(subject, body)

    assert result["classification"] == "legitimate"
    assert result["probability"] < 0.50
    assert result["available"] is True


def test_phishing_classifier_empty_body():
    result = global_phishing_classifier.predict(subject="", body="")
    assert result["classification"] == "legitimate"
    assert result["probability"] == 0.0
    assert result["confidence"] == "low"
    assert result["available"] is True


def test_phishing_classifier_non_english_graceful():
    # Non-English text should not crash inference
    result = global_phishing_classifier.predict(
        subject="Внимание: Вход в аккаунт",
        body="Мы зафиксировали вход в ваш аккаунт из необычного места."
    )
    assert isinstance(result, dict)
    assert result["available"] is True
    assert isinstance(result["probability"], float)


def test_phishing_classifier_missing_model_graceful():
    # Instantiate with a non-existent file path
    missing_classifier = PhishingClassifier(model_path="/tmp/non_existent_model_12345.joblib")
    assert missing_classifier.is_available is False

    result = missing_classifier.predict("Subject", "Body")
    assert result["available"] is False
    assert result["probability"] is None
    assert result["classification"] == "unknown"


def test_phishing_classifier_mock_model():
    mock_pipeline = MagicMock()
    # Mock predict_proba to return 89% phishing probability
    mock_pipeline.predict_proba.return_value = [[0.11, 0.89]]
    mock_pipeline.named_steps = {}

    classifier = PhishingClassifier(model_path="/dummy/path")
    classifier.pipeline = mock_pipeline

    result = classifier.predict("Any subject", "Any body text")
    assert result["classification"] == "phishing"
    assert result["probability"] == 0.89
    assert result["confidence"] == "high"


# =====================================================================
# 3. Threat Scorer Integration & Bounded Weight Tests
# =====================================================================

def test_threat_scorer_with_high_ml_phishing_probability():
    scorer = ThreatScorerService()

    # Create dummy EmailAnalysisResponse with 88% ML probability
    analysis = EmailAnalysisResponse(
        subject="Urgent Security Alert",
        plain_text_body="Reset your credentials immediately.",
        ml_phishing_probability=0.88
    )

    score_result = scorer.calculate_score(analysis)
    ml_reasons = [r for r in score_result.reasons if r.signal == "ml_phishing_signal"]

    assert len(ml_reasons) == 1
    assert ml_reasons[0].points == 10  # Bounded weight max 10 pts
    assert "88%" in ml_reasons[0].evidence


def test_threat_scorer_with_low_ml_probability_positive_evidence():
    scorer = ThreatScorerService()

    # Low ML probability (5%) contributes mitigating positive evidence
    analysis = EmailAnalysisResponse(
        subject="Sprint Retrospective",
        plain_text_body="Thanks for the great sprint everyone.",
        ml_phishing_probability=0.05
    )

    score_result = scorer.calculate_score(analysis)
    ml_pos = [p for p in score_result.positive_evidence if p.signal == "ml_low_risk_content"]

    assert len(ml_pos) == 1
    assert "5%" in ml_pos[0].evidence


def test_threat_scorer_with_none_ml_probability():
    scorer = ThreatScorerService()

    # ML unavailable (None) - deterministic scoring proceeds normally
    analysis = EmailAnalysisResponse(
        subject="Normal Message",
        plain_text_body="Hello world",
        ml_phishing_probability=None
    )

    score_result = scorer.calculate_score(analysis)
    ml_reasons = [r for r in score_result.reasons if r.signal == "ml_phishing_signal"]
    ml_pos = [p for p in score_result.positive_evidence if p.signal == "ml_low_risk_content"]

    assert len(ml_reasons) == 0
    assert len(ml_pos) == 0
    assert isinstance(score_result.score, int)


# =====================================================================
# 4. API Endpoints Integration Tests
# =====================================================================

def test_api_ml_classify_endpoint():
    payload = {
        "subject": "Urgent: Verify Your Microsoft Office 365 Password",
        "body": "Your account will be terminated unless you update credentials at http://office-verify.com."
    }
    response = client.post("/api/emails/ml-classify", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "classification" in data
    assert "probability" in data
    assert "confidence" in data
    assert data["available"] is True


def test_api_ml_classify_empty_payload():
    payload = {"subject": "", "body": ""}
    response = client.post("/api/emails/ml-classify", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == "legitimate"
    assert data["probability"] == 0.0


def test_api_analyze_email_includes_ml_fields():
    raw_eml = (
        b"From: security@alerts-security-center.com\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Immediate action: Verify your password now\r\n"
        b"Date: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <msg982104@alerts-security-center.com>\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"Your account has been locked. Please update your credentials at http://verify-password.net immediately.\r\n"
    )

    files = {"file": ("phishing_test.eml", io.BytesIO(raw_eml), "message/rfc822")}
    response = client.post("/api/emails/analyze", files=files)
    assert response.status_code == 200

    data = response.json()
    assert "ml_phishing_probability" in data
    assert "ml_assessment" in data
    if data["ml_assessment"]:
        assert "classification" in data["ml_assessment"]
        assert "probability" in data["ml_assessment"]
        assert data["ml_assessment"]["available"] is True
    assert "threat_score" in data
    assert "score" in data["threat_score"]


def test_api_analyze_email_failure_mode_graceful():
    # If the ML model throws an unexpected error, analyze_email continues and doesn't fail
    raw_eml = (
        b"From: test@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Test Email\r\n"
        b"Date: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <test-123@example.com>\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Hello world\r\n"
    )

    with patch.object(global_phishing_classifier, "predict", side_effect=RuntimeError("Simulated inference engine crash")):
        files = {"file": ("test.eml", io.BytesIO(raw_eml), "message/rfc822")}
        response = client.post("/api/emails/analyze", files=files)
        # Should succeed despite ML crash!
        assert response.status_code == 200
        data = response.json()
        assert data["ml_phishing_probability"] is None
        assert data["ml_assessment"] is None
        assert "threat_score" in data
