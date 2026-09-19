import io
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import Base, engine, SessionLocal
from backend.db.models import CaseModel, CaseEmailModel, EmailAnalysisModel, EvidenceModel

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_teardown_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        db.query(CaseEmailModel).delete()
        db.query(CaseModel).delete()
        db.query(EmailAnalysisModel).delete()
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.query(CaseEmailModel).delete()
        db.query(CaseModel).delete()
        db.query(EmailAnalysisModel).delete()
        db.commit()
    finally:
        db.close()


def test_dashboard_summary_empty():
    """Verify dashboard summary works cleanly when database is empty (no division by zero or errors)."""
    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    data = response.json()

    assert data["metrics"]["emails_analyzed"] == 0
    assert data["metrics"]["threats_detected"] == 0
    assert data["metrics"]["critical_emails"] == 0
    assert data["metrics"]["open_cases"] == 0

    assert data["severity_distribution"] == []
    assert data["analysis_trend"] == []
    assert data["top_suspicious_domains"] == []
    assert data["top_countries"] == []
    assert data["auth_failures"]["spf_failures"] == 0
    assert data["auth_failures"]["dkim_failures"] == 0
    assert data["auth_failures"]["dmarc_failures"] == 0
    assert data["auth_failures"]["total_evaluated"] == 0
    assert data["recent_cases"] == []
    assert data["recent_emails"] == []


def test_dashboard_summary_with_real_records():
    """Verify metrics and analytics aggregation with populated cases and analyzed emails."""
    db = SessionLocal()

    # Create 2 cases: 1 open, 1 resolved
    c1 = CaseModel(
        case_number="CASE-2026-TEST01",
        title="Spearphishing against CFO",
        severity="critical",
        status="investigating"
    )
    c2 = CaseModel(
        case_number="CASE-2026-TEST02",
        title="Spam newsletter",
        severity="low",
        status="resolved"
    )
    db.add_all([c1, c2])
    db.commit()

    # Create 3 email analyses
    now = datetime.now(timezone.utc)
    e1 = EmailAnalysisModel(
        subject="Urgent Wire Transfer",
        sender="attacker@spoofed-bank.com",
        threat_score=92.0,
        severity="critical",
        spf_result="FAIL",
        dkim_result="FAIL",
        dmarc_result="FAIL",
        domains_json=json.dumps(["spoofed-bank.com", "wire-portal.net"]),
        countries_json=json.dumps(["Russia", "United States"]),
        analyzed_at=now
    )
    e2 = EmailAnalysisModel(
        subject="Vendor Invoice Overdue",
        sender="accounting@supplier-portal.com",
        threat_score=65.0,
        severity="high",
        spf_result="SOFTFAIL",
        dkim_result="PASS",
        dmarc_result="FAIL",
        domains_json=json.dumps(["supplier-portal.com"]),
        countries_json=json.dumps(["Germany"]),
        analyzed_at=now
    )
    e3 = EmailAnalysisModel(
        subject="Weekly Team Lunch Menu",
        sender="catering@company.local",
        threat_score=5.0,
        severity="low",
        spf_result="PASS",
        dkim_result="PASS",
        dmarc_result="PASS",
        domains_json=json.dumps(["company.local"]),
        countries_json=json.dumps(["United States"]),
        analyzed_at=now
    )
    db.add_all([e1, e2, e3])
    db.commit()
    db.close()

    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    data = response.json()

    # Top metrics assertions
    metrics = data["metrics"]
    assert metrics["emails_analyzed"] == 3
    assert metrics["threats_detected"] == 2  # 92 and 65 (>= 50 or critical/high)
    assert metrics["critical_emails"] == 1   # 92 (>= 80 or critical)
    assert metrics["open_cases"] == 1       # only c1 is investigating; c2 is resolved

    # Severity distribution
    sev_map = {item["severity"]: item["count"] for item in data["severity_distribution"]}
    assert sev_map.get("critical") == 1
    assert sev_map.get("high") == 1
    assert sev_map.get("low") == 1

    # Suspicious domains (company.local is excluded if ending with .local)
    domain_map = {item["domain"]: item["count"] for item in data["top_suspicious_domains"]}
    assert "spoofed-bank.com" in domain_map
    assert "wire-portal.net" in domain_map
    assert "supplier-portal.com" in domain_map

    # Country distribution
    country_map = {item["country"]: item["count"] for item in data["top_countries"]}
    assert country_map["United States"] == 2
    assert country_map["Russia"] == 1
    assert country_map["Germany"] == 1

    # Auth failures
    auth = data["auth_failures"]
    assert auth["spf_failures"] == 2  # FAIL, SOFTFAIL
    assert auth["dkim_failures"] == 1  # 1 FAIL
    assert auth["dmarc_failures"] == 2  # 2 FAIL
    assert auth["total_evaluated"] == 3

    # Recent cases & emails
    assert len(data["recent_cases"]) == 2
    assert len(data["recent_emails"]) == 3


def test_dashboard_emails_pagination():
    """Verify paginated listing of analyzed emails."""
    db = SessionLocal()
    for i in range(5):
        db.add(EmailAnalysisModel(
            subject=f"Email Test {i}",
            sender=f"test{i}@example.com",
            threat_score=float(i * 20),
            severity="low" if i < 2 else "high",
            analyzed_at=datetime.now(timezone.utc)
        ))
    db.commit()
    db.close()

    res = client.get("/api/dashboard/emails?skip=0&limit=2")
    assert res.status_code == 200
    pdata = res.json()
    assert pdata["total"] == 5
    assert len(pdata["items"]) == 2
    assert pdata["skip"] == 0
    assert pdata["limit"] == 2

    # Next page
    res2 = client.get("/api/dashboard/emails?skip=2&limit=2")
    assert res2.status_code == 200
    pdata2 = res2.json()
    assert len(pdata2["items"]) == 2
    assert pdata2["items"][0]["id"] != pdata["items"][0]["id"]
