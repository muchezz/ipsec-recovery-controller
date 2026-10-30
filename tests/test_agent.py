from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from ipsec_recovery_controller.agent.app import create_app
from ipsec_recovery_controller.agent.cli import CertificateH11Protocol
from ipsec_recovery_controller.agent.config import AgentConfig, AgentConnection
from ipsec_recovery_controller.api.app import create_app as create_controller_app
from ipsec_recovery_controller.config import (
    AgentEndpoint,
    AlertRule,
    Config,
    Connection,
    Gateway,
    ServerConfig,
)
from ipsec_recovery_controller.diagnostics.inspection import Inspector
from ipsec_recovery_controller.gateway.https_agent import HTTPSAgentTransport
from ipsec_recovery_controller.gateway.local import LocalTransport
from ipsec_recovery_controller.gateway.ssh import InspectionError

OUTPUT = """Connections:
  ike: configured
Security Associations (1 up, 0 connecting):
  ike[7]: ESTABLISHED
  child{1}: INSTALLED, TUNNEL
  child{1}: 10.0.0.0/24 === 10.1.0.0/24
  child{2}: INSTALLED, TUNNEL
"""


class FakeLocal:
    def run(self, gateway, command):
        assert command == "ipsec statusall"
        return OUTPUT


def config(tmp_path, identity="controller"):
    return AgentConfig(
        server_cert=str(tmp_path / "server.crt"), server_key=str(tmp_path / "server.key"),
        client_ca=str(tmp_path / "ca.crt"), allowed_client_identity=identity,
        connections={"connection-1": AgentConnection(ike_connection="ike", child_connection="child")},
    )


def test_agent_requires_certificate_and_authorizes_local_mapping(tmp_path):
    app = create_app(config(tmp_path), FakeLocal())
    client = TestClient(app)
    assert client.get("/v1/healthz").status_code == 401
    assert client.get("/v1/associations").status_code == 401
    assert client.get("/v1/connections/other").status_code == 401


def test_agent_inspections_with_verified_scope(tmp_path):
    app = create_app(config(tmp_path), FakeLocal())
    app.add_middleware(CertMiddleware)
    client = TestClient(app)
    assert client.get("/v1/healthz").json()["api_version"] == "v1"
    result = client.get("/v1/connections/connection-1")
    assert result.status_code == 200
    assert result.json()["diagnostic"]["child_installed"] == 2
    assert result.json()["snapshot"]["child_sas"][0]["parent_ike_id"] == "7"
    assert client.get("/v1/connections/unknown").status_code == 404
    assert len(client.get("/v1/associations").json()["snapshot"]["child_sas"]) == 2


class CertMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        scope["client_cert_der"] = certificate_der()
        await self.app(scope, receive, send)


def certificate_der():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "controller")])).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "controller")])).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1))
        .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_local_allowlist_and_bounded_output(monkeypatch):
    import subprocess
    import sys

    original = subprocess.Popen
    seen = []
    script = {"code": "print('ok')"}

    def fake_popen(args, **kwargs):
        seen.append(args)
        return original([sys.executable, "-c", script["code"]], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    transport = LocalTransport(timeout_seconds=1)
    assert transport.run(None, "ipsec status") == "ok\n"
    assert seen[0] == [transport.binary, "status"]
    with pytest.raises(InspectionError, match="command_not_allowed"):
        transport.run(None, "ipsec up tunnel")
    script["code"] = "print('x' * 3000000)"
    with pytest.raises(InspectionError, match="output_limit"):
        transport.run(None, "ipsec statusall")
    script["code"] = "import time; time.sleep(5)"
    with pytest.raises(InspectionError, match="timeout"):
        transport.run(None, "ipsec statusall")


def issue_cert(ca_key, ca_cert, name, *, expired=False, server=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=3 if expired else 1))
        .not_valid_after(now - dt.timedelta(days=1) if expired else now + dt.timedelta(days=2)))
    if server:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
    return key, builder.sign(ca_key, hashes.SHA256())


def write_pem(path, key, cert):
    path.with_suffix(".key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    path.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


@pytest.fixture
def tls_server(tmp_path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")]))
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(ca_key, hashes.SHA256()))
    (tmp_path / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for name, expired, server in (("server", False, True), ("client", False, False),
                                  ("expired", True, False), ("stranger", False, False)):
        key, cert = issue_cert(ca_key, ca, "localhost" if server else (
            "controller" if name != "stranger" else "stranger"), expired=expired, server=server)
        write_pem(tmp_path / name, key, cert)
    untrusted_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    untrusted_ca = (x509.CertificateBuilder().subject_name(ca.subject).issuer_name(ca.subject)
                    .public_key(untrusted_key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - dt.timedelta(days=1))
                    .not_valid_after(now + dt.timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                    .sign(untrusted_key, hashes.SHA256()))
    key, cert = issue_cert(untrusted_key, untrusted_ca, "controller")
    write_pem(tmp_path / "untrusted", key, cert)
    cfg = config(tmp_path)
    cfg = cfg.model_copy(update={"server": ServerConfig(host="127.0.0.1", port=8766)})
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    uvconfig = uvicorn.Config(
        create_app(cfg, FakeLocal()), host="127.0.0.1", port=port, log_level="error",
        http=CertificateH11Protocol, ssl_certfile=cfg.server_cert,
        ssl_keyfile=cfg.server_key, ssl_ca_certs=cfg.client_ca, ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
    server = uvicorn.Server(uvconfig)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.02)
    assert server.started
    yield f"https://localhost:{port}", tmp_path
    server.should_exit = True
    thread.join(timeout=5)


def test_live_mtls_and_identity(tls_server):
    url, directory = tls_server
    def context(name=None):
        result = ssl.create_default_context(cafile=str(directory / "ca.crt"))
        if name:
            result.load_cert_chain(str(directory / f"{name}.crt"), str(directory / f"{name}.key"))
        return result

    with httpx.Client(verify=context("client"), trust_env=False) as client:
        response = client.get(url + "/v1/connections/connection-1")
        assert response.status_code == 200
        assert response.json()["diagnostic"]["state"] == "installed_unverified"
        # Exercise multiple requests on the same TLS connection.
        for _ in range(3):
            assert client.get(url + "/v1/healthz").status_code == 200
        assert client.get(url + "/v1/associations").status_code == 200
    endpoint = AgentEndpoint(
        url=url, ca_file=str(directory / "ca.crt"), client_cert=str(directory / "client.crt"),
        client_key=str(directory / "client.key"),
    )
    controller = Config(
        gateways={"g": Gateway(transport="agent", agent=endpoint)},
        connections={"connection-1": Connection(gateway="g", ike_connection="ike",
                                                child_connection="child")},
    )
    assert Inspector(controller).inspect("connection-1").child_installed == 2
    controller = controller.model_copy(update={"alerts": [
        AlertRule(name="TunnelMissing", connection="connection-1")]})
    webhook = TestClient(create_controller_app(controller)).post("/alerts", json={
        "version": "4", "receiver": "test", "status": "firing",
        "alerts": [{"status": "firing", "labels": {"alertname": "TunnelMissing"}}],
    })
    assert webhook.status_code == 200
    assert webhook.json()["decisions"][0]["decision"] == "installed_unverified"
    assert webhook.json()["recovery_executed"] is False
    assert TestClient(create_app(config(directory), FakeLocal())).post(
        "/v1/connections/connection-1/recover").status_code == 404
    mismatch = controller.model_copy(update={"connections": {
        "connection-1": Connection(gateway="g", ike_connection="wrong", child_connection="child")}})
    with pytest.raises(InspectionError, match="agent_mapping_mismatch"):
        Inspector(mismatch).inspect("connection-1")
    with httpx.Client(verify=context("stranger"), trust_env=False) as client:
        assert client.get(url + "/v1/healthz").status_code == 403
    for name in (None, "expired", "untrusted"):
        with (httpx.Client(verify=context(name), trust_env=False) as client,
              # TLS rejection surfaces differently across Python/OpenSSL builds.
              pytest.raises((httpx.RemoteProtocolError, httpx.ReadError,
                             httpx.WriteError, httpx.ConnectError))):
            client.get(url + "/v1/healthz")
        with httpx.Client(verify=context("client"), trust_env=False) as authorized:
            assert authorized.get(url + "/v1/healthz").status_code == 200
    with (httpx.Client(verify=True, trust_env=False) as client,
          pytest.raises(httpx.ConnectError)):
        client.get(url + "/v1/healthz")


def test_agent_unavailable_and_timeout(tls_server, monkeypatch):
    _, directory = tls_server
    endpoint = AgentEndpoint(
        url="https://localhost:1", ca_file=str(directory / "ca.crt"),
        client_cert=str(directory / "client.crt"), client_key=str(directory / "client.key"),
        connect_timeout_seconds=0.1, request_timeout_seconds=0.1,
    )
    gateway = Gateway(transport="agent", agent=endpoint)
    expected = Connection(gateway="g", ike_connection="ike", child_connection="child")
    with pytest.raises(InspectionError, match="agent_unavailable"):
        HTTPSAgentTransport().inspect(gateway, "connection-1", expected)

    def timed_out(*args, **kwargs):
        raise httpx.ReadTimeout("synthetic timeout")

    monkeypatch.setattr(httpx.Client, "stream", timed_out)
    with pytest.raises(InspectionError, match="timeout"):
        HTTPSAgentTransport().inspect(gateway, "connection-1", expected)


def test_filtering_and_ambiguous_evidence(tmp_path):
    from ipsec_recovery_controller.adapters.legacy_ipsec import parse_status
    from ipsec_recovery_controller.agent.app import filter_snapshot

    snapshot = parse_status(OUTPUT + "  unrelated{3}: INSTALLED, TUNNEL\n")
    mapping = AgentConnection(ike_connection="ike", child_connection="child",
                              local_selector="10.0.0.0/24", remote_selector="10.1.0.0/24")
    # Missing selectors must not be converted to a missing tunnel.
    with pytest.raises(InspectionError, match="association_ambiguous"):
        filter_snapshot(snapshot, [mapping])
    from dataclasses import replace

    snapshot = replace(snapshot, child_sas=(snapshot.child_sas[0], snapshot.child_sas[-1]))
    filtered = filter_snapshot(snapshot, [mapping])
    assert [sa.identifier for sa in filtered.child_sas] == ["1"]
    assert not filter_snapshot(snapshot, []).child_sas


@pytest.mark.parametrize("mutation", ["empty", "missing", "version", "state", "parent", "count", "mapping", "counter", "duplicate"])
def test_response_validation_fails_closed(mutation):
    from copy import deepcopy

    from fastapi.encoders import jsonable_encoder

    from ipsec_recovery_controller.adapters.legacy_ipsec import parse_status
    from ipsec_recovery_controller.diagnostics.inspection import evaluate_snapshot
    from ipsec_recovery_controller.gateway.agent_response import validate_response

    expected = Connection(gateway="g", ike_connection="ike", child_connection="child")
    snapshot = parse_status(OUTPUT)
    data = jsonable_encoder({"api_version": "v1", "mapping": {
        "ike_connection": "ike", "child_connection": "child", "local_selector": None,
        "remote_selector": None}, "snapshot": snapshot,
        "diagnostic": evaluate_snapshot(expected, snapshot)})
    assert validate_response(data, expected) == snapshot
    data = deepcopy(data)
    if mutation == "empty":
        data = []
    elif mutation == "missing":
        del data["snapshot"]["child_sas"]
    elif mutation == "version":
        data["api_version"] = "v2"
    elif mutation == "state":
        data["snapshot"]["child_sas"][0]["state"] = "bogus"
    elif mutation == "parent":
        data["snapshot"]["child_sas"][0]["parent_ike_id"] = "999"
    elif mutation == "count":
        data["diagnostic"]["child_installed"] = 0
    elif mutation == "mapping":
        del data["mapping"]["local_selector"]
    elif mutation == "counter":
        data["snapshot"]["child_sas"][0]["bytes_in"] = -1
    elif mutation == "duplicate":
        data["snapshot"]["child_sas"].append(data["snapshot"]["child_sas"][0])
    with pytest.raises((ValueError, TypeError, InspectionError)):
        validate_response(data, expected)
