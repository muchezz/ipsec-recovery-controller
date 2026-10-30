from fastapi.testclient import TestClient

from ipsec_recovery_controller.api.app import create_app
from ipsec_recovery_controller.config import AlertRule, Config, Connection, Gateway
from ipsec_recovery_controller.diagnostics.inspection import Inspector
from ipsec_recovery_controller.gateway.ssh import InspectionError


class FakeTransport:
    def run(self, gateway, command):
        return """Connections:
  ike:  192.0.2.1...192.0.2.2  IKEv2
Security Associations (1 up, 0 connecting):
  ike[1]: ESTABLISHED 1 minute ago
  child{1}: INSTALLED, TUNNEL
  child{2}: INSTALLED, TUNNEL
"""

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
    response = TestClient(create_app(CONFIG, Inspector(CONFIG, FakeTransport()))).post("/alerts", json=PAYLOAD)
    assert response.status_code == 200
    assert response.json()["recovery_executed"] is False
    assert response.json()["decisions"][0]["decision"] == "installed_unverified"
    assert response.json()["decisions"][0]["diagnostic"]["child_installed"] == 2


def test_inspection_failure_is_explicit():
    class FailingTransport:
        def run(self, gateway, command):
            raise InspectionError("unavailable")

    response = TestClient(create_app(CONFIG, Inspector(CONFIG, FailingTransport()))).post(
        "/alerts", json=PAYLOAD
    )
    assert response.status_code == 200
    assert response.json()["decisions"][0]["decision"] == "inspection_failed"
    assert response.json()["recovery_executed"] is False


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


def test_observe_never_inspects():
    class ForbiddenInspector:
        def inspect(self, connection):
            raise AssertionError("observe mode reached gateway inspection")

    config = CONFIG.model_copy(update={"mode": "observe"})
    response = TestClient(create_app(config, ForbiddenInspector())).post("/alerts", json=PAYLOAD)
    assert response.json()["decisions"][0]["decision"] == "observed"
    assert response.json()["recovery_executed"] is False


def test_same_alert_name_routes_to_explicit_child_and_standby_gateway():
    config = Config(
        gateways={"active": Gateway(host="192.0.2.10"), "standby": Gateway(host="192.0.2.11")},
        connections={
            "active-a": Connection(gateway="active", ike_connection="ike-a", child_connection="child-a"),
            "standby-b": Connection(gateway="standby", ike_connection="ike-b", child_connection="child-b"),
        },
        alerts=[
            AlertRule(name="TunnelMissing", connection="active-a", match_labels={"peer": "a"}),
            AlertRule(name="TunnelMissing", connection="standby-b", match_labels={"peer": "b"}),
        ],
    )
    config.validate_mappings()

    class RecordingInspector:
        def __init__(self):
            self.calls = []

        def inspect(self, connection):
            self.calls.append(connection)
            from ipsec_recovery_controller.diagnostics.models import Diagnostic

            return Diagnostic("unknown", None, 0, 0, 0, 0)

    inspector = RecordingInspector()
    payload = {**PAYLOAD, "alerts": [
        {"status": "firing", "labels": {"alertname": "TunnelMissing", "peer": "a"}},
        {"status": "firing", "labels": {"alertname": "TunnelMissing", "peer": "b"}},
        {"status": "firing", "labels": {"alertname": "TunnelMissing", "peer": "injected"}},
    ]}
    response = TestClient(create_app(config, inspector)).post("/alerts", json=payload)
    assert [entry["connection"] for entry in response.json()["decisions"]] == [
        "active-a", "standby-b", "unmapped",
    ]
    assert inspector.calls == ["active-a", "standby-b"]


def test_overlapping_alert_rules_fail_closed():
    config = Config(
        gateways=CONFIG.gateways,
        connections=CONFIG.connections,
        alerts=[
            AlertRule(name="TunnelMissing", connection="c"),
            AlertRule(name="TunnelMissing", connection="c", match_labels={"peer": "a"}),
        ],
    )
    response = TestClient(create_app(config, Inspector(config, FakeTransport()))).post(
        "/alerts", json={**PAYLOAD, "alerts": [
            {"status": "firing", "labels": {"alertname": "TunnelMissing", "peer": "a"}},
        ]},
    )
    assert response.json()["decisions"][0]["decision"] == "ambiguous_mapping"


def test_same_alert_name_can_select_children_with_same_name_and_different_selectors():
    class SelectorTransport:
        def run(self, gateway, command):
            return """Connections:
  ike: configured
Security Associations (1 up, 0 connecting):
  ike[1]: ESTABLISHED
  child{1}: INSTALLED, TUNNEL
  child{1}: 10.0.0.0/24 === 10.1.0.0/24
  child{2}: INSTALLED, TUNNEL
  child{2}: 10.0.2.0/24 === 10.1.2.0/24
"""

    config = Config(
        gateways=CONFIG.gateways,
        connections={
            "first": Connection(gateway="g", ike_connection="ike", child_connection="child",
                                local_selector="10.0.0.0/24", remote_selector="10.1.0.0/24"),
            "second": Connection(gateway="g", ike_connection="ike", child_connection="child",
                                 local_selector="10.0.2.0/24", remote_selector="10.1.2.0/24"),
        },
        alerts=[
            AlertRule(name="TunnelMissing", connection="first", match_labels={"segment": "first"}),
            AlertRule(name="TunnelMissing", connection="second", match_labels={"segment": "second"}),
        ],
    )
    payload = {**PAYLOAD, "alerts": [
        {"status": "firing", "labels": {"alertname": "TunnelMissing", "segment": "first"}},
        {"status": "firing", "labels": {"alertname": "TunnelMissing", "segment": "second"}},
    ]}
    result = TestClient(create_app(config, Inspector(config, SelectorTransport()))).post(
        "/alerts", json=payload
    ).json()
    assert [item["connection"] for item in result["decisions"]] == ["first", "second"]
    assert [item["decision"] for item in result["decisions"]] == [
        "installed_unverified", "installed_unverified",
    ]
    assert all(item["diagnostic"]["child_installed"] == 1 for item in result["decisions"])
