from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from ipsec_recovery_controller.api.app import Alert, create_app
from ipsec_recovery_controller.config import (
    AgentEndpoint,
    AlertRule,
    Config,
    Connection,
    Gateway,
    RecoveryPolicy,
)
from ipsec_recovery_controller.gateway.ssh import InspectionError
from ipsec_recovery_controller.helper import server
from ipsec_recovery_controller.helper.recovery import (
    HelperRecoveryConfig,
    Target,
    recover,
    validate_live,
)
from ipsec_recovery_controller.recovery import RecoveryGate, mapping_hash, recover_alert
from ipsec_recovery_controller.state import initialize_state

MISSING = """Status of IKE charon daemon (strongSwan 5.8.2, Linux test):
Connections:
  tunnel:  192.0.2.1...192.0.2.2  IKEv2, dpddelay=30s
  tunnel:   local: [test] uses pre-shared key authentication
  tunnel:   child:  10.0.0.0/24 === 10.1.0.0/24 TUNNEL, dpdaction=restart
Security Associations (1 up, 0 connecting):
  tunnel[1]: ESTABLISHED 1 minute ago
"""
CHILD = """  tunnel{1}: INSTALLED, TUNNEL
  tunnel{1}: 10.0.0.0/24 === 10.1.0.0/24
"""
CONNECTION = Connection(gateway="g", ike_connection="tunnel", child_connection="tunnel",
                        local_selector="10.0.0.0/24", remote_selector="10.1.0.0/24",
                        recovery_enabled=True)
TARGET = Target(connection=CONNECTION, active_address="192.0.2.1")


def policy(tmp_path, **kwargs):
    if tmp_path.is_dir() and not (tmp_path / "recovery.sqlite3").exists():
        initialize_state(tmp_path)
    return RecoveryPolicy(state_directory=str(tmp_path), **kwargs)


def test_only_genuine_missing_allowed():
    assert validate_live(MISSING, TARGET) == "1"
    assert validate_live(MISSING + CHILD, TARGET, installed=True) == "1"


@pytest.mark.parametrize("output", [
    MISSING + CHILD,
    MISSING + CHILD.replace("tunnel{", "other{"),
    MISSING + CHILD + CHILD.replace("{1}", "{2}"),
    MISSING.replace("(1 up, 0 connecting)", "(2 up, 0 connecting)") + "  tunnel[2]: ESTABLISHED\n",
    MISSING.replace("ESTABLISHED", "CONNECTING").replace("1 up, 0 connecting", "0 up, 1 connecting"),
    MISSING + "  tunnel{1}: CREATED\n",
    MISSING + "  tunnel{1}: DELETING\n",
    MISSING.replace("5.8.2", "5.9.0"), MISSING[:-1],
    MISSING.replace("10.1.0.0/24", "10.2.0.0/24"),
    MISSING.replace("Connections:", "Unknown:"),
    MISSING + "  tunnel[1]: Tasks active: CHILD_CREATE\n",
    MISSING.replace("  tunnel:   child:", "  other:  a...b  IKEv2\n  tunnel:   child:"),
])
def test_unsafe_live_states_rejected(output):
    with pytest.raises((InspectionError, IndexError)):
        validate_live(output, TARGET)


def test_missing_recovered_and_persistently_deduplicated(tmp_path, monkeypatch):
    outputs = iter([MISSING, MISSING + CHILD])
    monkeypatch.setattr(server, "statusall", lambda: next(outputs))
    commands = []

    def command(argv):
        commands.append(argv)
        if argv[0] == "/usr/sbin/ip":
            return json.dumps([{"flags": ["UP"], "addr_info": [{"local": "192.0.2.1", "preferred_life_time": 4294967295}]}])
        assert argv == ["/usr/sbin/ipsec", "up", "tunnel"]
        return "success"

    monkeypatch.setattr(server, "command", command)
    config = HelperRecoveryConfig(enabled=True, policy=policy(tmp_path), targets={"c": TARGET})
    assert recover(config, "c", "a" * 64, mapping_hash(CONNECTION), int(time.time()) + 60) == "recovered"
    assert recover(config, "c", "a" * 64, mapping_hash(CONNECTION), int(time.time()) + 60) == "duplicate_alert"
    assert recover(config, "c", "b" * 64, mapping_hash(CONNECTION), int(time.time()) + 60) == "cooldown"
    assert sum(argv[1] == "up" for argv in commands) == 1


@pytest.mark.parametrize("case", ["standby", "installed", "duplicate", "uninspectable", "postcheck"])
def test_helper_failure_never_retries(tmp_path, monkeypatch, case):
    calls = []
    outputs = iter([MISSING if case == "postcheck" else MISSING + CHILD])
    monkeypatch.setattr(server, "statusall", lambda: next(outputs))

    def command(argv):
        if argv[0] == "/usr/sbin/ip":
            if case == "uninspectable":
                raise InspectionError("unavailable")
            return json.dumps([] if case == "standby" else [
                {"flags": ["UP"], "addr_info": [{"local": "192.0.2.1", "preferred_life_time": 4294967295}]}])
        calls.append(argv)
        return "success"

    monkeypatch.setattr(server, "command", command)
    config = HelperRecoveryConfig(enabled=True, policy=policy(tmp_path), targets={"c": TARGET})
    assert recover(config, "c", "a" * 64, mapping_hash(CONNECTION), int(time.time()) + 60) == "recovery_failed"
    assert recover(config, "c", "a" * 64, mapping_hash(CONNECTION), int(time.time()) + 60) == "duplicate_alert"
    assert len(calls) == (1 if case == "postcheck" else 0)


def test_cross_instance_global_lock_and_cooldown(tmp_path):
    entered, release = threading.Event(), threading.Event()
    results = []

    def operation():
        entered.set()
        assert release.wait(5)
        return "recovered"

    thread = threading.Thread(target=lambda: results.append(
        RecoveryGate(policy(tmp_path)).run("c", "a", operation)))
    thread.start()
    try:
        assert entered.wait(5)
        assert RecoveryGate(policy(tmp_path)).run("other", "b", lambda: pytest.fail("concurrent")) == "recovery_busy"
    finally:
        release.set()
        thread.join(5)
    assert results == ["recovered"]
    assert RecoveryGate(policy(tmp_path)).run("c", "b", lambda: pytest.fail("cooldown")) == "cooldown"


def test_storm_and_failed_admission_survive_new_gate(tmp_path):
    p = policy(tmp_path, storm_threshold=2)
    gate = RecoveryGate(p)
    assert gate.run("c", "a", lambda: "recovery_failed") == "recovery_failed"
    assert RecoveryGate(p).run("c", "a", lambda: pytest.fail("duplicate")) == "duplicate_alert"
    assert RecoveryGate(p).run("c", "a", lambda: pytest.fail("storm")) == "circuit_open"
    assert RecoveryGate(p).run("other", "b", lambda: pytest.fail("breaker")) == "circuit_open"


def test_missing_persistent_directory_fails_closed(tmp_path):
    assert RecoveryGate(policy(tmp_path / "absent")).run("c", "a", lambda: pytest.fail("storage")) == "recovery_failed"


def controller(tmp_path):
    return Config(mode="recover", webhook_token="secret", recovery=policy(tmp_path),
                  gateways={"g": Gateway(transport="agent", agent=AgentEndpoint(
                      url="https://example.invalid:8766", ca_file="/ca", client_cert="/cert", client_key="/key"))},
                  connections={"c": CONNECTION},
                  alerts=[AlertRule(name="PakakobeIPsecTunnelMissing", connection="c")])


def alert(**kwargs):
    data = {"status": "firing", "labels": {"alertname": "PakakobeIPsecTunnelMissing", "command": "; reboot"},
            "fingerprint": "abc", "startsAt": (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat()}
    return Alert(**(data | kwargs))


def test_controller_uses_configured_target_and_incident_identity(tmp_path):
    class Remote:
        def __init__(self):
            self.calls = []

        def initiate(self, gateway, identifier, expected, event):
            self.calls.append((identifier, expected))
            return "recovered"

    remote = Remote()
    config, event = controller(tmp_path), alert()
    assert recover_alert(config, "c", event, remote) == "recovered"
    assert recover_alert(config, "c", event.model_copy(update={"fingerprint": "different"}), remote) == "duplicate_alert"
    assert remote.calls == [("c", CONNECTION)]


@pytest.mark.parametrize("change", [{"startsAt": "bad"}, {"startsAt": "2026-01-01"},
                                    {"startsAt": datetime.now(timezone.utc).isoformat()},
                                    {"fingerprint": None}])
def test_malformed_and_premature_alerts_never_recover(tmp_path, change):
    assert recover_alert(controller(tmp_path), "c", alert(**change)) == "recovery_alert_invalid"


def test_recovery_requires_authentication_and_valid_alert_status(tmp_path):
    config = controller(tmp_path)
    client = TestClient(create_app(config))
    payload = {"version": "4", "status": "firing", "receiver": "test", "alerts": [alert().model_dump()]}
    assert client.post("/alerts", json=payload).status_code == 401
    payload["alerts"][0]["status"] = "garbage"
    assert client.post("/alerts", json=payload, headers={"X-IPsec-Controller-Token": "secret"}).status_code == 422


def test_unsupported_names_and_selector_layouts_rejected():
    for change in ({"ike_connection": "parent"}, {"child_connection": "-bad"},
                   {"local_selector": None}, {"remote_selector": "0.0.0.0/0,10.0.0.0/24"}):
        with pytest.raises(ValueError):
            Target(connection=CONNECTION.model_copy(update=change), active_address="192.0.2.1")


def test_controller_webhook_recovers_once_and_never_recovers_resolved(tmp_path, monkeypatch):
    from ipsec_recovery_controller.gateway.https_agent import HTTPSAgentTransport

    calls = []
    monkeypatch.setattr(HTTPSAgentTransport, "initiate", lambda self, *args: calls.append(args) or "recovered")
    client = TestClient(create_app(controller(tmp_path)))
    payload = {"version": "4", "status": "firing", "receiver": "test", "alerts": [alert().model_dump()]}
    headers = {"X-IPsec-Controller-Token": "secret"}
    response = client.post("/alerts", json=payload, headers=headers).json()
    assert response["recovery_executed"] is True
    assert client.post("/alerts", json=payload, headers=headers).json()["decisions"][0]["decision"] == "duplicate_alert"
    payload["status"] = "resolved"
    assert client.post("/alerts", json=payload, headers=headers).json()["decisions"][0]["decision"] == "not_firing"
    assert len(calls) == 1


def test_mapping_mismatch_and_disabled_helper_never_execute(tmp_path):
    config = HelperRecoveryConfig(enabled=True, policy=policy(tmp_path), targets={"c": TARGET})
    with pytest.raises(InspectionError, match="recovery_mapping_mismatch"):
        recover(config, "c", "a" * 64, "b" * 64, int(time.time()) + 60)
    with pytest.raises(InspectionError, match="recovery_not_allowed"):
        recover(config.model_copy(update={"enabled": False}), "c", "a" * 64, mapping_hash(CONNECTION), int(time.time()) + 60)


def test_equivalent_incident_timezones_deduplicate(tmp_path):
    class Remote:
        def initiate(self, *args):
            return "recovered"

    config, event = controller(tmp_path), alert()
    assert recover_alert(config, "c", event, Remote()) == "recovered"
    same = datetime.fromisoformat(event.startsAt).astimezone(timezone(timedelta(hours=3)))
    assert recover_alert(config, "c", event.model_copy(update={"startsAt": same.isoformat()}), Remote()) == "duplicate_alert"


def test_uncertain_operation_holds_global_admission_across_instances(tmp_path):
    gate = RecoveryGate(policy(tmp_path))
    assert gate.run("c", "a", lambda: "recovery_failed") == "recovery_failed"
    assert RecoveryGate(policy(tmp_path)).run("other", "b", lambda: pytest.fail("uncertain overlap")) == "recovery_busy"


def test_expired_request_cannot_initiate(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "command", lambda *args: pytest.fail("expired command"))
    cfg = HelperRecoveryConfig(enabled=True, policy=policy(tmp_path), targets={"c": TARGET})
    assert recover(cfg, "c", "a" * 64, mapping_hash(CONNECTION), int(time.time()) - 1) == "recovery_failed"


@pytest.mark.parametrize("damage", ["missing", "empty", "corrupt", "schema"])
def test_missing_or_corrupt_database_fails_closed(tmp_path, damage):
    p = policy(tmp_path)
    path = tmp_path / "recovery.sqlite3"
    if damage == "missing":
        path.unlink()
    elif damage == "empty":
        path.write_bytes(b"")
    elif damage == "corrupt":
        path.write_bytes(b"not a sqlite database")
    else:
        import sqlite3
        with sqlite3.connect(path) as db:
            db.execute("DROP TABLE attempts")
    assert RecoveryGate(p).run("c", "a", lambda: pytest.fail("damaged state")) == "recovery_failed"
    if damage == "missing":
        assert not path.exists()


def test_initializer_never_resets_existing_state(tmp_path):
    initialize_state(tmp_path)
    with pytest.raises(FileExistsError):
        initialize_state(tmp_path)


@pytest.mark.parametrize("threshold", [10, 100])
def test_30_simultaneous_alerts_are_serialized_and_storm_limited(tmp_path, monkeypatch, threshold):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from ipsec_recovery_controller.gateway.https_agent import HTTPSAgentTransport

    config = controller(tmp_path)
    config.recovery.storm_threshold = threshold
    start = threading.Barrier(31)
    release = threading.Event()
    calls = []

    def remote(*args):
        calls.append(args)
        assert release.wait(20)
        return "recovered"

    monkeypatch.setattr(HTTPSAgentTransport, "initiate", remote)
    app = create_app(config)
    payload = {"version": "4", "status": "firing", "receiver": "test", "alerts": [alert().model_dump()]}

    def deliver():
        start.wait(timeout=10)
        with TestClient(app) as client:
            response = client.post("/alerts", json=payload, headers={"X-IPsec-Controller-Token": "secret"})
            assert response.status_code == 200
            return response.json()["decisions"][0]["decision"]

    outcomes = []
    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = [pool.submit(deliver) for _ in range(30)]
        start.wait(timeout=10)
        try:
            for future in as_completed(futures, timeout=15):
                outcomes.append(future.result())
                if len(outcomes) == 29:
                    break
        finally:
            release.set()
        outcomes = [future.result(timeout=10) for future in futures]
    assert len(calls) <= 1
    assert set(outcomes) <= {"recovered", "recovery_busy", "duplicate_alert", "circuit_open"}
    if threshold == 10:
        assert "circuit_open" in outcomes
    else:
        assert len(calls) == 1
        assert outcomes.count("recovered") == 1


@pytest.mark.parametrize("change_at", [2, 3])
def test_ha_ownership_loss_before_or_after_up_is_not_success(tmp_path, monkeypatch, change_at):
    addresses, commands = [], []
    snapshots = iter([MISSING, MISSING + CHILD])
    monkeypatch.setattr(server, "statusall", lambda: next(snapshots))

    def command(argv):
        if argv[0] == "/usr/sbin/ip":
            addresses.append(argv)
            if len(addresses) >= change_at:
                return "[]"
            return json.dumps([{"flags": ["UP"], "addr_info": [
                {"local": "192.0.2.1", "preferred_life_time": 100}]}])
        commands.append(argv)
        return "success"

    monkeypatch.setattr(server, "command", command)
    cfg = HelperRecoveryConfig(enabled=True, policy=policy(tmp_path), targets={"c": TARGET})
    assert recover(cfg, "c", "a" * 64, mapping_hash(CONNECTION), int(time.time()) + 60) == "recovery_failed"
    assert len(commands) == (1 if change_at == 3 else 0)
    assert recover(cfg, "c", "a" * 64, mapping_hash(CONNECTION), int(time.time()) + 60) == "duplicate_alert"


def test_timeout_after_remote_side_effect_is_uncertain_and_persistent(tmp_path):
    cfg = controller(tmp_path)
    incident = alert()
    calls = []

    class Remote:
        def initiate(self, *args):
            calls.append(args)
            raise InspectionError("timeout")

    assert recover_alert(cfg, "c", incident, Remote()) == "recovery_failed"
    restarted = Config.model_validate(cfg.model_dump())
    assert recover_alert(restarted, "c", incident, Remote()) == "duplicate_alert"
    assert len(calls) == 1


def test_process_crash_keeps_incident_and_global_hold(tmp_path):
    import subprocess
    import sys

    p = policy(tmp_path)
    script = """
import os, sys
from ipsec_recovery_controller.config import RecoveryPolicy
from ipsec_recovery_controller.recovery import RecoveryGate
RecoveryGate(RecoveryPolicy(state_directory=sys.argv[1])).run('c', 'incident', lambda: os._exit(23))
"""
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], check=False)
    assert result.returncode == 23
    assert RecoveryGate(p).run("c", "incident", lambda: pytest.fail("crashed incident replay")) == "duplicate_alert"
    assert RecoveryGate(p).run("other", "new", lambda: pytest.fail("crashed overlap")) == "recovery_busy"


@pytest.mark.parametrize("state", ["CREATED", "REKEYING", "DELETING"])
def test_negotiating_or_deleting_children_block_initiation(state):
    with pytest.raises(InspectionError, match="recovery_child_present"):
        validate_live(MISSING + f"  tunnel{{9}}: {state}, TUNNEL\n", TARGET)


def test_source_built_582_live_missing_fixture():
    from pathlib import Path

    output = (Path(__file__).parent / "fixtures/strongswan-5.8.2-isolated-missing.txt").read_text()
    target = Target(connection=Connection(
        gateway="isolated", ike_connection="isolated-test", child_connection="isolated-test",
        local_selector="10.10.0.0/24", remote_selector="10.20.0.0/24", recovery_enabled=True),
        active_address="127.0.0.1")
    assert validate_live(output, target) == "1"
