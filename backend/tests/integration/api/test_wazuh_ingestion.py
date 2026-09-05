from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url
from shieldchain.main import create_app


@pytest.fixture
def wazuh_client(tmp_path: Path) -> Iterator[TestClient]:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'wazuh.db'}")
    Base.metadata.create_all(engine)
    settings = Settings(
        _env_file=None,
        simulation_step_delay_ms=0,
        wazuh_webhook_token="test-wazuh-token",
        wazuh_review_min_severity=12,
        assistant_data_root=tmp_path / "assistant",
    )
    app = create_app(database_engine=engine, settings=settings)
    with TestClient(app) as client:
        yield client
    engine.dispose()


def payload(*, external_id: str = "wazuh-001", severity: int = 12) -> dict[str, object]:
    return {
        "external_id": external_id,
        "occurred_at": "2026-07-28T10:00:00Z",
        "severity": severity,
        "rule_id": "100201",
        "title": "Suspicious PowerShell network connection",
        "agent_id": "001",
        "agent_name": "PC-023",
        "mitre_ids": ["T1059.001", "T1071.001"],
        "process_name": "powershell.exe",
        "parent_process_name": "WINWORD.EXE",
        "source_ip": "10.10.23.17",
        "destination_ip": "198.51.100.24",
        "destination_port": 443,
        "evidence": {"rule_level": severity, "network_direction": "outbound"},
    }


def test_ingestion_requires_configured_token(wazuh_client: TestClient) -> None:
    response = wazuh_client.post("/api/v1/integrations/wazuh/alerts", json=payload())

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "wazuh_ingestion_unauthorized"


def test_high_risk_alert_creates_one_review_only_case(wazuh_client: TestClient) -> None:
    headers = {"X-ShieldChain-Wazuh-Token": "test-wazuh-token"}

    created = wazuh_client.post(
        "/api/v1/integrations/wazuh/alerts", json=payload(), headers=headers
    )
    repeated = wazuh_client.post(
        "/api/v1/integrations/wazuh/alerts", json=payload(), headers=headers
    )
    correlated = wazuh_client.post(
        "/api/v1/integrations/wazuh/alerts",
        json=payload(external_id="wazuh-003"),
        headers=headers,
    )
    listed = wazuh_client.get("/api/v1/integrations/wazuh/alerts")
    cases = wazuh_client.get("/api/v1/integrations/wazuh/cases")

    assert created.status_code == repeated.status_code == correlated.status_code == 202
    assert created.json()["created"] is True
    assert repeated.json()["created"] is False
    review_case = created.json()["review_case"]
    assert review_case == repeated.json()["review_case"]
    assert review_case["id"] == correlated.json()["review_case"]["id"]
    assert review_case["tracking_id"] == correlated.json()["review_case"]["tracking_id"]
    assert review_case["tracking_id"] == "WAZ-2026-0001"
    assert review_case["status"] == "needs_review"
    assert review_case["source"] == "wazuh"
    assert review_case["endpoint"] == "PC-023"
    assert listed.json()["items"][0]["review_case"]["id"] == review_case["id"]
    assert [item["id"] for item in cases.json()["items"]] == [review_case["id"]]


def test_lower_severity_alert_stays_in_inbox_without_review_case(wazuh_client: TestClient) -> None:
    response = wazuh_client.post(
        "/api/v1/integrations/wazuh/alerts",
        json=payload(external_id="wazuh-002", severity=11),
        headers={"X-ShieldChain-Wazuh-Token": "test-wazuh-token"},
    )

    assert response.status_code == 202
    assert response.json()["created"] is True
    assert response.json()["review_case"] is None
    assert wazuh_client.get("/api/v1/integrations/wazuh/cases").json()["items"] == []


def test_operator_explicitly_starts_one_case_bound_agent_run(
    wazuh_client: TestClient,
) -> None:
    created = wazuh_client.post(
        "/api/v1/integrations/wazuh/alerts",
        json=payload(external_id="wazuh-investigate"),
        headers={"X-ShieldChain-Wazuh-Token": "test-wazuh-token"},
    )
    case_id = created.json()["review_case"]["id"]

    investigated = wazuh_client.post(
        f"/api/v1/integrations/wazuh/cases/{case_id}/investigate",
        json={"rule_ttl_seconds": 60},
    )

    assert investigated.status_code == 201
    assert investigated.json()["run_id"]
    assert investigated.json()["response_plan"]["status"] == "completed_advisory"
    assert investigated.json()["response_plan"]["action_count"] == 0
    listed = wazuh_client.get("/api/v1/integrations/wazuh/cases").json()["items"]
    assert listed[0]["status"] == "investigated"
    assert listed[0]["run_id"] == investigated.json()["run_id"]

    repeated = wazuh_client.post(
        f"/api/v1/integrations/wazuh/cases/{case_id}/investigate",
        json={"rule_ttl_seconds": 60},
    )
    assert repeated.status_code == 409
    assert repeated.json()["error"]["code"] == "wazuh_investigation_rejected"
