import pytest

from ipsec_recovery_controller.adapters.legacy_ipsec import LegacyIPsecAdapter, parse_status
from ipsec_recovery_controller.config import Connection, Gateway
from ipsec_recovery_controller.diagnostics.inspection import evaluate_snapshot
from ipsec_recovery_controller.gateway.ssh import InspectionError, SSHTransport

OUTPUT = """Status of IKE charon daemon (strongSwan 5.9):
Connections:
  partner-ike:  192.0.2.1...192.0.2.2  IKEv2
Security Associations (1 up, 1 connecting):
  partner-ike[1]: ESTABLISHED 30 seconds ago
  partner-child{1}: INSTALLED, TUNNEL
  partner-child{2}: INSTALLED, TUNNEL
  other[3]: CONNECTING
  other{3}: CREATED, TUNNEL
"""
CONNECTION = Connection(gateway="g", ike_connection="partner-ike", child_connection="partner-child")


def test_parser_and_multiple_children():
    snapshot = parse_status(OUTPUT, "ipsec statusall")
    result = evaluate_snapshot(CONNECTION, snapshot)
    assert result.state == "installed_unverified"
    assert result.configured
    assert result.child_installed == 2
    assert result.ike_established == 1


def test_missing_and_negotiating_child():
    output = OUTPUT.replace("  partner-child{1}: INSTALLED, TUNNEL\n", "").replace(
        "  partner-child{2}: INSTALLED, TUNNEL\n", ""
    )
    snapshot = parse_status(output, "ipsec statusall")
    assert evaluate_snapshot(CONNECTION, snapshot).state == "child_missing"
    negotiating = parse_status(output + "  partner-child{5}: CREATED, TUNNEL\n", "ipsec statusall")
    assert evaluate_snapshot(CONNECTION, negotiating).state == "child_negotiating"


def test_missing_and_negotiating_ike():
    output = OUTPUT.replace("  partner-ike[1]: ESTABLISHED 30 seconds ago\n", "").replace(
        "Security Associations (1 up, 1 connecting):",
        "Security Associations (0 up, 1 connecting):",
    )
    assert evaluate_snapshot(CONNECTION, parse_status(output, "ipsec statusall")).state == "unknown"
    output = output.replace("  partner-child{1}: INSTALLED, TUNNEL\n", "").replace(
        "  partner-child{2}: INSTALLED, TUNNEL\n", ""
    )
    assert evaluate_snapshot(CONNECTION, parse_status(output, "ipsec statusall")).state == "ike_missing"
    output += "  partner-ike[4]: CONNECTING\n"
    output = output.replace("Security Associations (0 up, 1 connecting):", "Security Associations (0 up, 2 connecting):")
    assert evaluate_snapshot(CONNECTION, parse_status(output, "ipsec statusall")).state == "ike_negotiating"


def test_unrecognized_output_fails_closed():
    with pytest.raises(InspectionError):
        parse_status("unexpected message", "ipsec statusall")


@pytest.mark.parametrize("code", ["authentication_failed", "timeout", "host_key_failed"])
def test_no_status_fallback(code):
    class Transport:
        def __init__(self):
            self.commands = []

        def run(self, gateway, command):
            self.commands.append(command)
            if command == "ipsec statusall":
                raise InspectionError(code)
            return "Security Associations (0 up, 0 connecting):\n"

    transport = Transport()
    with pytest.raises(InspectionError):
        LegacyIPsecAdapter(transport).inspect(Gateway(host="192.0.2.10"))
    assert transport.commands == ["ipsec statusall"]


def test_ssh_fixed_command_and_host_key_verification():
    gateway = Gateway(host="2001:db8::10", ssh_user="observer", ssh_port=2222)
    with pytest.raises(InspectionError):
        SSHTransport().run(gateway, "ipsec up tunnel")


def test_missing_or_truncated_sa_section_fails_closed():
    for output in (
        "Connections:\n  partner-ike: configured\n",
        "Connections:\nSecurity Associations (1 up, 0 connecting):\n",
        "Connections:\nSecurity Associations (bad):\n",
        "Connections:\nSecurity Associations (0 up, 0 connecting):",
        "Connections:\nSecurity Associations (0 up, 0 connecting):\n  broken[1",
    ):
        with pytest.raises(InspectionError) as exc:
            parse_status(output)
        assert exc.value.code == "malformed_output"


def test_sa_details_and_distinct_selectors_are_preserved():
    output = """Connections:
  partner-ike: configured
Security Associations (1 up, 0 connecting):
  partner-ike[7]: ESTABLISHED
  partner-ike[7]: IKEv2 SPIs: abc_i def_r
  partner-child{11}: INSTALLED, TUNNEL
  partner-child{11}: ESP SPIs: 0102_i 0304_o
  partner-child{11}: 10.0.0.0/24 === 10.1.0.0/24
  partner-child{11}: 12 bytes_i (1 pkt), 34 bytes_o (2 pkts)
  partner-child{12}: INSTALLED, TUNNEL
  partner-child{12}: 10.0.2.0/24 === 10.1.2.0/24
"""
    snapshot = parse_status(output)
    assert [sa.identifier for sa in snapshot.child_sas] == ["11", "12"]
    assert [sa.parent_ike_id for sa in snapshot.child_sas] == ["7", "7"]
    assert [sa.local_selector for sa in snapshot.child_sas] == ["10.0.0.0/24", "10.0.2.0/24"]
    assert snapshot.child_sas[0].remote_selector == "10.1.0.0/24"
    assert snapshot.child_sas[0].bytes_in == 12
    assert snapshot.child_sas[0].bytes_out == 34
    assert snapshot.child_sas[0].spi == "0102_i 0304_o"
    assert evaluate_snapshot(CONNECTION, snapshot).state == "installed_unverified"
    selected = CONNECTION.model_copy(update={
        "local_selector": "10.0.2.0/24", "remote_selector": "10.1.2.0/24",
    })
    result = evaluate_snapshot(selected, snapshot)
    assert result.state == "installed_unverified"
    assert result.child_installed == 1
    absent = CONNECTION.model_copy(update={
        "local_selector": "10.0.9.0/24", "remote_selector": "10.1.9.0/24",
    })
    assert evaluate_snapshot(absent, snapshot).state == "child_missing"


def test_unconfigured_and_status_without_configuration_are_conservative():
    unconfigured = parse_status("Connections:\nSecurity Associations (0 up, 0 connecting):\n  none\n")
    assert evaluate_snapshot(CONNECTION, unconfigured).state == "unconfigured"
    unknown = parse_status("Security Associations (0 up, 0 connecting):\n")
    assert evaluate_snapshot(CONNECTION, unknown).state == "unknown"


def test_parser_failure_does_not_run_second_command():
    class Transport:
        def __init__(self):
            self.calls = []

        def run(self, gateway, command):
            self.calls.append(command)
            return "Connections:\n  partner-ike: configured\n"

    transport = Transport()
    with pytest.raises(InspectionError) as exc:
        LegacyIPsecAdapter(transport).inspect(Gateway(host="192.0.2.10"))
    assert exc.value.code == "malformed_output"
    assert transport.calls == ["ipsec statusall"]


def test_installed_child_under_other_ike_is_unknown():
    output = """Connections:
  partner-ike: configured
Security Associations (2 up, 0 connecting):
  partner-ike[1]: ESTABLISHED
  other[2]: ESTABLISHED
  partner-child{3}: INSTALLED, TUNNEL
"""
    assert evaluate_snapshot(CONNECTION, parse_status(output)).state == "unknown"


def test_ssh_bounded_output_and_structured_errors(monkeypatch):
    import subprocess
    import sys

    original = subprocess.Popen
    seen = []
    script = {"code": "import sys; sys.stdout.write('ok\\n')"}

    def fake_popen(args, **kwargs):
        seen.append(args)
        return original([sys.executable, "-c", script["code"]], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    gateway = Gateway(host="2001:db8::10", ssh_user="observer", ssh_port=2222)
    assert SSHTransport().run(gateway, "ipsec statusall") == "ok\n"
    assert seen[0][-2:] == ["observer@2001:db8::10", "ipsec statusall"]
    assert "StrictHostKeyChecking=yes" in seen[0]
    assert "ControlMaster=no" in seen[0]
    assert "ClearAllForwardings=yes" in seen[0]

    class SmallTransport(SSHTransport):
        STDOUT_LIMIT = 8
        STDERR_LIMIT = 8

    script["code"] = "import sys; sys.stdout.write('x' * 1000)"
    with pytest.raises(InspectionError) as exc:
        SmallTransport().run(gateway, "ipsec statusall")
    assert exc.value.code == "output_limit"
    script["code"] = "import sys; sys.stderr.write('x' * 1000)"
    with pytest.raises(InspectionError) as exc:
        SmallTransport().run(gateway, "ipsec statusall")
    assert exc.value.code == "output_limit"
    script["code"] = "import sys; sys.stderr.write('Permission denied'); sys.exit(255)"
    with pytest.raises(InspectionError) as exc:
        SSHTransport().run(gateway, "ipsec statusall")
    assert exc.value.code == "authentication_failed"


def test_ssh_timeout_is_structured(monkeypatch):
    import subprocess
    import sys

    original = subprocess.Popen

    def fake_popen(args, **kwargs):
        return original([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    with pytest.raises(InspectionError) as exc:
        SSHTransport().run(Gateway(host="192.0.2.10", ssh_timeout_seconds=1), "ipsec statusall")
    assert exc.value.code == "timeout"
