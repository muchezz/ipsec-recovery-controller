from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading

import pytest

from ipsec_recovery_controller.gateway.ssh import InspectionError
from ipsec_recovery_controller.helper import server


def exchange(request, allowed_uid):
    client, broker = socket.socketpair()
    thread = threading.Thread(target=lambda: _handle(broker, allowed_uid))
    thread.start()
    with client:
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        result = bytearray()
        while chunk := client.recv(65536):
            result.extend(chunk)
    thread.join(timeout=3)
    assert not thread.is_alive()
    return json.loads(result)


def _handle(connection, uid):
    with connection:
        server.handle(connection, uid)


def test_kernel_peer_credentials_deny_other_identity(monkeypatch):
    def forbidden():
        raise AssertionError("unauthorized caller reached subprocess")

    monkeypatch.setattr(server, "statusall", forbidden)
    client, broker = socket.socketpair()
    with client, broker:
        assert server.peer_uid(broker) == os.getuid()
        server.handle(broker, os.getuid() + 1)
        assert json.loads(client.recv(1024)) == {"error": "helper_unauthorized"}


@pytest.mark.parametrize("payload", [b"", b"status\n", b"statusall;id\n", b"statusall\nextra",
                                     b"/usr/sbin/ipsec statusall\n", b"x" * 33,
                                     b'{"command":"statusall"}', b"statusall connection\n"])
def test_only_exact_operation_accepted(payload, monkeypatch):
    def forbidden():
        raise AssertionError("unsupported operation reached subprocess")

    monkeypatch.setattr(server, "statusall", forbidden)
    assert exchange(payload, os.getuid()) == {"error": "helper_operation_not_allowed"}


def test_success_and_command_error(monkeypatch):
    monkeypatch.setattr(server, "statusall", lambda: "synthetic output\n")
    assert exchange(b"statusall\n", os.getuid()) == {"output": "synthetic output\n"}

    def fail():
        raise InspectionError("timeout")

    monkeypatch.setattr(server, "statusall", fail)
    assert exchange(b"statusall\n", os.getuid()) == {"error": "timeout"}


@pytest.mark.parametrize("script,code", [
    ("print('ok')", None),
    ("import time; time.sleep(30)", "timeout"),
    ("print('x'*100000)", "output_limit"),
    ("import sys; sys.stderr.write('x'*100000)", "output_limit"),
    ("import sys; sys.exit(1)", "helper_command_failed"),
])
def test_fixed_argv_bounding_and_reaping(monkeypatch, script, code):
    original = subprocess.Popen
    processes = []

    def popen(args, **kwargs):
        assert args == ["/usr/sbin/ipsec", "statusall"]
        assert kwargs["start_new_session"] is True
        assert kwargs["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
        assert kwargs["cwd"] == "/"
        assert not kwargs.get("shell", False)
        process = original([sys.executable, "-c", script], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(server, "COMMAND_TIMEOUT", 0.2)
    monkeypatch.setattr(server, "STDOUT_LIMIT", 128)
    monkeypatch.setattr(server, "STDERR_LIMIT", 128)
    if code:
        with pytest.raises(InspectionError, match=code):
            server.statusall()
    else:
        assert server.statusall() == "ok\n"
    assert processes[0].returncode is not None
    with pytest.raises(ChildProcessError):
        os.waitpid(processes[0].pid, os.WNOHANG)


def test_client_allowlist_and_backend_selection(tmp_path):
    from ipsec_recovery_controller.agent.app import create_app
    from ipsec_recovery_controller.agent.config import AgentConfig
    from ipsec_recovery_controller.gateway.helper import HelperTransport

    with pytest.raises(InspectionError, match="command_not_allowed"):
        HelperTransport(str(tmp_path / "missing")).run(None, "ipsec up anything")
    with pytest.raises(InspectionError, match="helper_unavailable"):
        HelperTransport(str(tmp_path / "missing")).run(None, "ipsec statusall")
    cfg = AgentConfig(server_cert="/tmp/server", server_key="/tmp/key", client_ca="/tmp/ca",
                      allowed_client_identity="example", inspection_backend="helper",
                      helper_socket=str(tmp_path / "missing"))
    assert create_app(cfg).title == "IPsec Recovery Agent"


def test_requests_are_serialized(monkeypatch):
    import time

    pairs = [socket.socketpair(), socket.socketpair()]
    class Done(Exception):
        pass

    class Listener:
        def __init__(self):
            self.connections = iter(pair[1] for pair in pairs)

        def accept(self):
            try:
                return next(self.connections), None
            except StopIteration as exc:
                raise Done from exc

    active = 0
    maximum = 0
    def inspect():
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        time.sleep(0.02)
        active -= 1
        return "ok"

    monkeypatch.setattr(server, "statusall", inspect)
    for client, _ in pairs:
        client.sendall(b"statusall\n")
        client.shutdown(socket.SHUT_WR)
    with pytest.raises(Done):
        server.serve(Listener(), os.getuid())
    for client, _ in pairs:
        with client:
            assert json.loads(client.recv(1024)) == {"output": "ok"}
    assert maximum == 1


def test_request_deadline_prevents_idle_client(monkeypatch):
    monkeypatch.setattr(server, "REQUEST_TIMEOUT", 0.02)
    client, broker = socket.socketpair()
    with client, broker:
        server.handle(broker, os.getuid())
        assert json.loads(client.recv(1024)) == {"error": "helper_request_failed"}


def test_timeout_kills_descendants(monkeypatch, tmp_path):
    import time
    original = subprocess.Popen
    pid_file = tmp_path / "descendant.pid"
    script = ("import subprocess,sys,time; "
              "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
              f"open({str(pid_file)!r},'w').write(str(p.pid)); time.sleep(30)")
    monkeypatch.setattr(subprocess, "Popen", lambda args, **kwargs:
                        original([sys.executable, "-c", script], **kwargs))
    monkeypatch.setattr(server, "COMMAND_TIMEOUT", 0.5)
    with pytest.raises(InspectionError, match="timeout"):
        server.statusall()
    pid = int(pid_file.read_text())
    for _ in range(100):
        stat = __import__("pathlib").Path(f"/proc/{pid}/stat")
        try:
            state = stat.read_text().split()[2]
        except (FileNotFoundError, ProcessLookupError):
            break
        if state == "Z":
            break
        time.sleep(0.01)
    else:
        pytest.fail("descendant survived helper timeout")


def test_client_rejects_non_root_socket_peer(tmp_path):
    from ipsec_recovery_controller.gateway.helper import HelperTransport
    if os.getuid() == 0:
        pytest.skip("requires a non-root test process")
    path = str(tmp_path / "helper.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        listener.listen(1)
        with pytest.raises(InspectionError, match="helper_identity_failed"):
            HelperTransport(path).run(None, "ipsec statusall")


def test_helper_transport_roundtrip(tmp_path, monkeypatch):
    from ipsec_recovery_controller.adapters.legacy_ipsec import parse_status
    from ipsec_recovery_controller.gateway import helper

    path = str(tmp_path / "broker.sock")
    output = "Connections:\nSecurity Associations (0 up, 0 connecting):\n  none\n"
    # Positive protocol test is unprivileged; the separate test verifies real root-peer rejection.
    monkeypatch.setattr(helper, "peer_uid", lambda connection: 0)
    monkeypatch.setattr(server, "statusall", lambda: output)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        listener.listen(1)
        def accept():
            connection, _ = listener.accept()
            _handle(connection, os.getuid())
        thread = threading.Thread(target=accept)
        thread.start()
        snapshot = parse_status(helper.HelperTransport(path).run(None, "ipsec statusall"))
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert snapshot.connections_known
        assert not snapshot.ike_sas
