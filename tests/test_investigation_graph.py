import io
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.schemas.graph import NodeType, InvestigationGraphResponse
from backend.services.graph_service import InvestigationGraphService, global_graph_service
from backend.schemas.email import (
    EmailAnalysisResponse,
    AuthenticationAnalysis,
    ProtocolResult,
    ThreatScoreResult
)

client = TestClient(app)

SAMPLE_RICH_EMAIL_DATA = {
    "id": "email-test-001",
    "email_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "subject": "Urgent: Verify Your PayPal Account",
    "from_header": "Security Center <service@paypa1-security.com>",
    "to": ["victim@example.com"],
    "reply_to": "bounce@shadow-mailer.org",
    "date": "2026-09-07T12:00:00Z",
    "threat_score": {
        "score": 88,
        "severity": "critical",
        "reasons": [
            {"signal": "spf_fail", "label": "SPF Fail", "points": 15},
            {"signal": "lookalike", "label": "Lookalike Domain", "points": 25}
        ]
    },
    "ml_phishing_probability": 0.92,
    "urls": [
        "https://paypa1-security.com/login",
        "https://paypa1-security.com/account/verify",
        "https://external-cdn.net/logo.png"
    ],
    "domain_intelligence": {
        "paypa1-security.com": {
            "domain_age_days": 5,
            "newly_registered_domain": True,
            "registration": {"registrar": "NameCheap, Inc."},
            "dns": {
                "a": ["198.51.100.22", "198.51.100.23"],
                "aaaa": []
            },
            "lookalike": {
                "suspected_brand": "paypal.com",
                "similarity": 0.94,
                "confidence_label": "High confidence brand impersonation"
            }
        },
        "external-cdn.net": {
            "domain_age_days": 1200,
            "newly_registered_domain": False,
            "registration": {"registrar": "MarkMonitor"},
            "dns": {
                "a": ["198.51.100.22"]  # Same IP to test shared IP resolution!
            }
        }
    },
    "ip_intelligence": {
        "198.51.100.22": {
            "country": "US",
            "asn": "AS64512",
            "org": "Threat Hosting Corp",
            "is_proxy_vpn_tor": True
        },
        "198.51.100.23": {
            "country": "US",
            "asn": "AS64512",  # Same ASN to test shared ASN node!
            "org": "Threat Hosting Corp",
            "is_proxy_vpn_tor": False
        }
    },
    "relay_analysis": {
        "earliest_observable_node": {
            "earliest_observable_ip": "198.51.100.22"
        }
    },
    "attachments": [
        {
            "filename": "security_invoice.pdf.exe",
            "mime_type": "application/x-msdos-program",
            "size": 245760,
            "sha256": "1111222233334444555566667777888899990000aaaa"
        }
    ]
}


# =====================================================================
# 1. Graph Generation Tests
# =====================================================================

def test_graph_generation_complete():
    service = InvestigationGraphService()
    graph = service.build_graph(SAMPLE_RICH_EMAIL_DATA, case_id="CASE-2026-99")

    assert isinstance(graph, InvestigationGraphResponse)
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0

    # Verify node types present
    node_types = {n.type for n in graph.nodes}
    assert NodeType.EMAIL in node_types
    assert NodeType.EMAIL_ADDRESS in node_types
    assert NodeType.DOMAIN in node_types
    assert NodeType.URL in node_types
    assert NodeType.IP in node_types
    assert NodeType.ASN in node_types
    assert NodeType.ATTACHMENT in node_types
    assert NodeType.CASE in node_types

    # Verify edge labels
    edge_labels = {e.label for e in graph.edges}
    assert "SENT_FROM" in edge_labels
    assert "SENT_TO" in edge_labels
    assert "REPLY_TO" in edge_labels
    assert "CONTAINS_URL" in edge_labels
    assert "RESOLVES_TO_DOMAIN" in edge_labels
    assert "RESOLVES_TO_IP" in edge_labels
    assert "BELONGS_TO_ASN" in edge_labels
    assert "HAS_ATTACHMENT" in edge_labels
    assert "ASSOCIATED_WITH_CASE" in edge_labels

    # Verify Summary
    assert graph.summary.total_nodes == len(graph.nodes)
    assert graph.summary.total_edges == len(graph.edges)
    assert graph.summary.has_high_risk_entities is True


# =====================================================================
# 2. Deduplication & Unique Identifiers Tests
# =====================================================================

def test_graph_deduplication():
    """
    Test that identical entities are not duplicated in nodes or edges.
    """
    service = InvestigationGraphService()
    graph = service.build_graph(SAMPLE_RICH_EMAIL_DATA)

    node_ids = [n.id for n in graph.nodes]
    edge_ids = [e.id for e in graph.edges]

    # Every node ID must be unique
    assert len(node_ids) == len(set(node_ids))
    # Every edge ID must be unique
    assert len(edge_ids) == len(set(edge_ids))

    # paypa1-security.com is referenced by From header, Domain Intelligence, and 2 URLs
    domain_nodes = [n for n in graph.nodes if n.id == "domain:paypa1-security.com"]
    assert len(domain_nodes) == 1
    # Check that metadata was merged (contains lookalike info)
    assert domain_nodes[0].metadata.get("is_lookalike") is True
    assert domain_nodes[0].metadata.get("suspected_brand") == "paypal.com"


# =====================================================================
# 3. Shared Nodes Across Multiple Entities
# =====================================================================

def test_shared_nodes():
    """
    Verify that multiple URLs pointing to the same domain link to the single shared domain node,
    and multiple IPs in the same ASN link to the single shared ASN node.
    """
    service = InvestigationGraphService()
    graph = service.build_graph(SAMPLE_RICH_EMAIL_DATA)

    # 1. Multiple URLs -> Same Domain
    domain_target_edges = [
        e for e in graph.edges
        if e.target == "domain:paypa1-security.com" and e.label == "RESOLVES_TO_DOMAIN"
    ]
    # At least two URLs resolve to paypa1-security.com
    assert len(domain_target_edges) == 2

    # 2. Multiple IPs -> Same ASN (AS64512)
    asn_nodes = [n for n in graph.nodes if n.type == NodeType.ASN and "64512" in n.id]
    assert len(asn_nodes) == 1
    asn_target_edges = [
        e for e in graph.edges
        if e.target == asn_nodes[0].id and e.label == "BELONGS_TO_ASN"
    ]
    # Both 198.51.100.22 and 198.51.100.23 link to AS64512
    assert len(asn_target_edges) == 2


# =====================================================================
# 4. Graph Filtering Tests
# =====================================================================

def test_graph_filtering():
    service = InvestigationGraphService()
    full_graph = service.build_graph(SAMPLE_RICH_EMAIL_DATA)

    # Filter only Domain and IP nodes
    filtered = service.filter_graph(full_graph, allowed_types=[NodeType.DOMAIN, NodeType.IP])

    assert len(filtered.nodes) > 0
    for node in filtered.nodes:
        assert node.type in (NodeType.DOMAIN, NodeType.IP)

    # Verify no dangling edges exist: all edge endpoints must exist in filtered nodes
    valid_ids = {n.id for n in filtered.nodes}
    for edge in filtered.edges:
        assert edge.source in valid_ids
        assert edge.target in valid_ids

    # Edges between Domain and IP (RESOLVES_TO_IP) should remain preserved
    resolves_edges = [e for e in filtered.edges if e.label == "RESOLVES_TO_IP"]
    assert len(resolves_edges) > 0


# =====================================================================
# 5. Empty and Null Graph Handling
# =====================================================================

def test_empty_graph_handling():
    service = InvestigationGraphService()

    # None
    graph_none = service.build_graph(None)
    assert graph_none.nodes == []
    assert graph_none.edges == []
    assert graph_none.summary.total_nodes == 0

    # Empty dictionary
    graph_empty = service.build_graph({})
    assert graph_empty.nodes == []
    assert graph_empty.edges == []

    # Bare minimal email
    graph_minimal = service.build_graph({"subject": "Hello"})
    assert len(graph_minimal.nodes) == 1
    assert graph_minimal.nodes[0].type == NodeType.EMAIL
    assert graph_minimal.edges == []


# =====================================================================
# 6. API Endpoint Integration Tests
# =====================================================================

def test_api_investigation_graph_endpoint():
    payload = EmailAnalysisResponse(
        subject="Test Phishing Campaign",
        plain_text_body="Click https://evil-domain.com/login",
        urls=["https://evil-domain.com/login"]
    )

    response = client.post("/api/emails/investigation-graph", json=payload.model_dump(by_alias=True))
    assert response.status_code == 200
    data = response.json()

    assert "nodes" in data
    assert "edges" in data
    assert "summary" in data
    assert len(data["nodes"]) >= 2  # Email and URL
    assert any(n["type"] == "Email" for n in data["nodes"])
    assert any(n["type"] == "URL" for n in data["nodes"])


def test_api_investigation_graph_filter_endpoint():
    # First generate graph
    payload = EmailAnalysisResponse(
        subject="Test Phishing Campaign",
        urls=["https://evil-domain.com/login"]
    )
    res1 = client.post("/api/emails/investigation-graph", json=payload.model_dump(by_alias=True))
    assert res1.status_code == 200
    initial_graph = res1.json()

    # Filter for only URL nodes
    filter_payload = {
        "graph": initial_graph,
        "node_types": ["URL"]
    }
    res_filtered = client.post(
        "/api/emails/investigation-graph/filter",
        json=filter_payload
    )
    assert res_filtered.status_code == 200
    filtered_data = res_filtered.json()
    assert len(filtered_data["nodes"]) > 0
    assert all(n["type"] == "URL" for n in filtered_data["nodes"])


def test_analyze_email_pipeline_includes_investigation_graph():
    """
    Verify POST /api/emails/analyze produces an investigation_graph field.
    """
    sample_eml = b"""From: alerts@bank-verification.com
To: user@target.org
Subject: Urgent: Verify Security
Date: Mon, 07 Sep 2026 12:00:00 +0000

Please verify your credentials at http://bank-verification.com/login immediately.
"""
    files = {"file": ("test_graph.eml", io.BytesIO(sample_eml), "message/rfc822")}
    response = client.post("/api/emails/analyze", files=files)
    assert response.status_code == 200
    data = response.json()

    assert "investigation_graph" in data
    assert data["investigation_graph"] is not None
    graph = data["investigation_graph"]
    assert "nodes" in graph
    assert "edges" in graph
    assert "summary" in graph
    assert len(graph["nodes"]) > 0
    assert any(n["type"] == "Email" for n in graph["nodes"])
    assert any(n["type"] == "Email Address" for n in graph["nodes"])
