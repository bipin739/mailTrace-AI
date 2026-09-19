import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import Base, get_db
from backend.db.models import CaseModel, CaseEmailModel
from backend.services.campaign_correlator import CampaignCorrelator


# -----------------------------------------------------------------------------
# Test Fixtures & In-Memory Database
# -----------------------------------------------------------------------------

@pytest.fixture
def test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def correlator():
    return CampaignCorrelator()


# -----------------------------------------------------------------------------
# Unit Tests for Correlation Engine
# -----------------------------------------------------------------------------

def test_no_overlap(correlator):
    """Verifies that completely distinct emails return zero score and empty shared indicators."""
    email_a = {
        "subject": "Staff Meeting Agenda - Q3 Marketing",
        "from": "alice@marketing-internal.net",
        "reply_to": "alice@marketing-internal.net",
        "domains": ["marketing-internal.net"],
        "ips": ["198.51.100.10"],
        "attachments": [{"filename": "agenda.pdf", "sha256": "1111111111111111111111111111111111111111111111111111111111111111"}]
    }
    email_b = {
        "subject": "System Upgrade Maintenance Notice",
        "from": "sysadmin@corp-it-support.org",
        "reply_to": "sysadmin@corp-it-support.org",
        "domains": ["corp-it-support.org"],
        "ips": ["203.0.113.50"],
        "attachments": [{"filename": "guide.pdf", "sha256": "2222222222222222222222222222222222222222222222222222222222222222"}]
    }

    res = correlator.direct_compare(email_a, email_b)
    assert res.correlation_score == 0.0
    assert len(res.shared_indicators) == 0
    assert res.relationship_label == "Inconclusive / No significant relationship"
    assert "same attacker" not in res.relationship_label.lower()


def test_weak_overlap(correlator):
    """Verifies that minor overlap (e.g. similar subject line alone) produces a low score."""
    email_a = {
        "subject": "Urgent: Immediate Review of Account Suspension Notice",
        "from": "security@bank-corp-portal.com",
        "domains": ["bank-corp-portal.com"],
        "ips": ["198.51.100.1"]
    }
    email_b = {
        "subject": "Re: Urgent: Immediate Review of Account Suspension Notice",
        "from": "notifications@telecom-billing-alert.org",
        "domains": ["telecom-billing-alert.org"],
        "ips": ["203.0.113.2"]
    }

    res = correlator.direct_compare(email_a, email_b)
    assert 0.05 <= res.correlation_score <= 0.25
    assert any(ind.type == "subject" for ind in res.shared_indicators)
    # Never claim same attacker
    assert "same attacker" not in res.relationship_label.lower()


def test_strong_overlap(correlator):
    """Verifies that multiple shared signals yield high score and 'Likely campaign relationship'."""
    shared_ip = "185.220.101.55"
    shared_domain = "paypa1-secure-billing.com"
    shared_reply_to = "dropzone@paypa1-secure-billing.com"
    shared_hash = "a" * 64

    email_a = {
        "subject": "Urgent Invoice Payment Overdue - Action Required",
        "from": "billing@paypa1-secure-billing.com",
        "reply_to": shared_reply_to,
        "domains": [shared_domain],
        "ips": [shared_ip],
        "attachments": [{"filename": "invoice.pdf.exe", "sha256": shared_hash}]
    }
    email_b = {
        "subject": "Notice: Urgent Invoice Payment Overdue",
        "from": "accounting@paypa1-secure-billing.com",
        "reply_to": shared_reply_to,
        "domains": [shared_domain],
        "ips": [shared_ip],
        "attachments": [{"filename": "remittance_advice.exe", "sha256": shared_hash}]
    }

    res = correlator.direct_compare(email_a, email_b)
    assert res.correlation_score >= 0.75
    assert res.relationship_label == "Likely campaign relationship"
    assert "same attacker" not in res.relationship_label.lower()
    assert "same attacker" not in res.shared_evidence_summary.lower()

    # Check shared indicators
    ind_types = {i.type for i in res.shared_indicators}
    assert "attachment_hash" in ind_types
    assert "ip" in ind_types
    assert "domain" in ind_types
    assert "reply_to" in ind_types


def test_same_attachment_hash(correlator):
    """Verifies that sharing the exact same attachment SHA-256 is a very strong isolated signal."""
    malware_hash = "d5f6e8a7b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"

    email_a = {
        "subject": "Job Application - Senior Accountant",
        "from": "john.applicant@gmail.com",
        "domains": ["unrelated-firm.org"],
        "ips": ["198.51.100.20"],
        "attachments": [{"filename": "Resume_John.docm", "sha256": malware_hash}]
    }
    email_b = {
        "subject": "RFQuotation - Supply Order 2026",
        "from": "procurement@supplier-portal.net",
        "domains": ["supplier-portal.net"],
        "ips": ["203.0.113.80"],
        "attachments": [{"filename": "Specs_Sheet.xlsm", "sha256": malware_hash}]
    }

    res = correlator.direct_compare(email_a, email_b)
    assert res.correlation_score >= 0.35
    assert any(i.type == "attachment_hash" and i.value == malware_hash for i in res.shared_indicators)
    assert "1 attachment hash" in res.shared_evidence_summary


def test_shared_ip(correlator):
    """Verifies that a shared hosting/relay IP triggers a strong correlation signal."""
    malicious_ip = "194.26.29.112"

    email_a = {
        "subject": "Package Delivery Update Pending",
        "from": "tracking@shipping-status-fed.com",
        "domains": ["shipping-status-fed.com"],
        "ips": [malicious_ip]
    }
    email_b = {
        "subject": "Cryptocurrency Wallet Verification",
        "from": "alert@coin-vault-auth.io",
        "domains": ["coin-vault-auth.io"],
        "ips": [malicious_ip]
    }

    res = correlator.direct_compare(email_a, email_b)
    assert res.correlation_score >= 0.20
    assert any(i.type == "ip" and i.value == malicious_ip for i in res.shared_indicators)
    assert "1 IP" in res.shared_evidence_summary


def test_false_positive_control(correlator):
    """
    Verifies that common infrastructure, public resolvers, generic webmail,
    private IPs, and empty files do NOT cause false correlation.
    """
    # 1. Generic webmail domains (e.g. gmail.com) should not correlate unless full email matches
    email_webmail_a = {
        "subject": "Invoice for Consulting",
        "from": "legit_person_1@gmail.com",
        "domains": ["gmail.com"]
    }
    email_webmail_b = {
        "subject": "Birthday Dinner Plans",
        "from": "legit_person_2@gmail.com",
        "domains": ["gmail.com"]
    }
    res_webmail = correlator.direct_compare(email_webmail_a, email_webmail_b)
    # Should have 0 domain correlation
    assert not any(i.type == "domain" for i in res_webmail.shared_indicators)

    # 2. Public DNS resolvers (8.8.8.8, 1.1.1.1) and private IPs (192.168.1.1) should not correlate
    email_ips_a = {
        "subject": "Weekly Report A",
        "ips": ["8.8.8.8", "1.1.1.1", "192.168.1.100", "127.0.0.1"]
    }
    email_ips_b = {
        "subject": "Monthly Report B",
        "ips": ["8.8.8.8", "1.1.1.1", "192.168.1.200", "127.0.0.1"]
    }
    res_ips = correlator.direct_compare(email_ips_a, email_ips_b)
    assert not any(i.type == "ip" for i in res_ips.shared_indicators)
    assert res_ips.correlation_score == 0.0

    # 3. Empty attachment SHA-256 should not correlate
    empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    email_empty_a = {
        "subject": "Letter A",
        "attachments": [{"filename": "blank1.txt", "sha256": empty_hash}]
    }
    email_empty_b = {
        "subject": "Document B",
        "attachments": [{"filename": "blank2.txt", "sha256": empty_hash}]
    }
    res_empty = correlator.direct_compare(email_empty_a, email_empty_b)
    assert not any(i.type == "attachment_hash" for i in res_empty.shared_indicators)


def test_strict_non_attribution_language(correlator):
    """Verifies that non-attribution rules are strictly maintained across score tiers."""
    tiers = [0.0, 0.15, 0.25, 0.50, 0.85, 1.0]
    for s in tiers:
        label = correlator.get_relationship_label(s)
        assert "same attacker" not in label.lower()
        assert "attacker" not in label.lower()
        assert "actor" not in label.lower() or "activity" in label.lower()


# -----------------------------------------------------------------------------
# End-to-End API Route Tests
# -----------------------------------------------------------------------------

def test_api_correlate_email_against_cases(client, test_db):
    """Tests POST /api/correlation/email endpoint with real DB cases."""
    # Create Case 1 with malicious indicators
    case1 = CaseModel(
        id="c1111111-1111-1111-1111-111111111111",
        case_number="CASE-2026-000010",
        title="CEO Fraud Wire Scam",
        description="Wire transfer phishing campaign",
        severity="critical",
        status="investigating"
    )
    test_db.add(case1)
    test_db.commit()

    # Add email to case
    case_email = CaseEmailModel(
        case_id=case1.id,
        email_id="sample-wire-01",
        subject="URGENT: Executive Wire Transfer Authorization",
        sender="cfo@exec-finance-corp.net",
        indicators_json='{"domains": ["exec-finance-corp.net"], "ips": ["185.100.87.42"], "reply_to": "wires@exec-finance-corp.net", "urls": ["http://exec-finance-corp.net/auth"]}'
    )
    test_db.add(case_email)
    test_db.commit()

    # Correlate incoming email sharing the domain and IP
    incoming_payload = {
        "subject": "Follow-Up: Executive Wire Transfer Authorization",
        "from": "accounting@exec-finance-corp.net",
        "reply_to": "wires@exec-finance-corp.net",
        "domains": ["exec-finance-corp.net"],
        "ips": ["185.100.87.42"]
    }

    res = client.post("/api/correlation/email?min_score=0.15", json=incoming_payload)
    assert res.status_code == 200
    data = res.json()

    assert data["correlation_score"] >= 0.50
    assert len(data["related_cases"]) == 1
    assert data["related_cases"][0]["case_number"] == "CASE-2026-000010"
    assert "same attacker" not in data["relationship_label"].lower()
    assert len(data["shared_indicators"]) >= 2


def test_api_correlate_case_against_cases(client, test_db):
    """Tests GET /api/cases/{case_id}/correlation endpoint comparing cases."""
    shared_ip = "194.5.249.18"

    # Case A
    case_a = CaseModel(
        id="c2222222-2222-2222-2222-222222222222",
        case_number="CASE-2026-000021",
        title="Phishing Campaign Alpha",
        severity="high",
        status="open"
    )
    test_db.add(case_a)
    test_db.commit()

    email_a = CaseEmailModel(
        case_id=case_a.id,
        email_id="email-a",
        subject="Invoice Overdue 1",
        indicators_json=f'{{"ips": ["{shared_ip}"], "domains": ["evil-cloud-login.com"]}}'
    )
    test_db.add(email_a)

    # Case B (shares IP)
    case_b = CaseModel(
        id="c3333333-3333-3333-3333-333333333333",
        case_number="CASE-2026-000022",
        title="Phishing Campaign Beta",
        severity="high",
        status="investigating"
    )
    test_db.add(case_b)
    test_db.commit()

    email_b = CaseEmailModel(
        case_id=case_b.id,
        email_id="email-b",
        subject="Invoice Overdue 2",
        indicators_json=f'{{"ips": ["{shared_ip}"], "domains": ["different-domain.org"]}}'
    )
    test_db.add(email_b)
    test_db.commit()

    # Query Case A correlation
    res = client.get(f"/api/cases/{case_a.id}/correlation")
    assert res.status_code == 200
    data = res.json()

    assert len(data["related_cases"]) == 1
    assert data["related_cases"][0]["case_number"] == "CASE-2026-000022"
    assert any(i["type"] == "ip" and i["value"] == shared_ip for i in data["shared_indicators"])


def test_api_direct_compare_endpoint(client):
    """Tests POST /api/correlation/compare endpoint."""
    payload = {
        "entity_a": {
            "subject": "Direct Deposit Verification",
            "ips": ["185.120.40.10"],
            "domains": ["payroll-portal-verify.com"]
        },
        "entity_b": {
            "subject": "Urgent Direct Deposit Verification",
            "ips": ["185.120.40.10"],
            "domains": ["payroll-portal-verify.com"]
        }
    }

    res = client.post("/api/correlation/compare", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["correlation_score"] >= 0.40
    assert len(data["shared_indicators"]) >= 2
    assert "same attacker" not in data["relationship_label"].lower()
