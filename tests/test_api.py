from fastapi.testclient import TestClient

from ipsec_recovery_controller.api.app import create_app
from ipsec_recovery_controller.config import Config, Gateway, Connection, AlertRule

CONFIG = Config(
    gateways={"g": Gateway(host="192.0.2.10")},
    connections={"c": Connection(gateway="g", ike_connection="ike", child_connection="child")},
    alerts=[AlertRule(name="TunnelMissing", connection="c")],
)
PAYLOAD = {
    "version": "4",
    "receiver": "ipsec-recovery",
    "status": "firing",
    "alerts": [{"status": "firing", "labels": {"alertname": "TunnelMissing"}, "fingerprint": "abc"}],
}


def test_health():
    assert TestClient(create_app(CONFIG)).get("/healthz").json()["status"] == "ok"


def test_dry_run_does_not_execute():
    response = TestClient(create_app(CONFIG)).post("/alerts", json=PAYLOAD)
    assert response.status_code == 200
    assert response.json()["recovery_executed"] is False
    assert response.json()["decisions"][0]["decision"] == "inspection_not_implemented"


def test_unknown_alert_skipped():
    payload = {**PAYLOAD, "alerts": [{"status": "firing", "labels": {"alertname": "Other"}}]}
    response = TestClient(create_app(CONFIG)).post("/alerts", json=payload)
    assert response.json()["decisions"][0]["decision"] == "unmapped"


def test_invalid_webhook_rejected():
    assert TestClient(create_app(CONFIG)).post("/alerts", json={"hello": "world"}).status_code == 422


def test_wrong_version_rejected():
    assert TestClient(create_app(CONFIG)).post("/alerts", json={**PAYLOAD, "version": "3"}).status_code == 422


def test_resolved_never_actionable():
    payload = {**PAYLOAD, "status": "resolved"}
    response = TestClient(create_app(CONFIG)).post("/alerts", json=payload)
    assert response.json()["decisions"][0]["decision"] == "not_firing"


def test_authentication():
    config = CONFIG.model_copy(update={"webhook_token": "secret"})
    client = TestClient(create_app(config))
    assert client.post("/alerts", json=PAYLOAD).status_code == 401
    assert client.post("/alerts", json=PAYLOAD, headers={"X-IPsec-Controller-Token": "secret"}).status_code == 200


def test_payload_limit():
    config = CONFIG.model_copy(update={"max_payload_bytes": 1024})
    assert TestClient(create_app(config)).post("/alerts", content=b"x" * 1025).status_code == 413
