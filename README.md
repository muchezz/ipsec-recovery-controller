# IPsec Recovery Controller

A small, safe Alertmanager webhook controller for strongSwan IPsec diagnostics.

**v0.3.0 is read-only.** It validates Alertmanager v4 webhooks, maps alert labels to configured connections, records audit decisions, and exposes Prometheus metrics. `observe` does not connect to gateways. `dry-run` inspects legacy strongSwan gateways over SSH or a gateway-local HTTPS agent. Neither mode changes IPsec state.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[test]"
cp config.example.yaml config.yaml
IPSEC_CONTROLLER_CONFIG=./config.yaml ipsec-recovery-controller
```

In another terminal:

```bash
curl -sS http://127.0.0.1:8765/healthz
curl -sS http://127.0.0.1:8765/metrics
curl -sS -X POST http://127.0.0.1:8765/alerts \
  -H 'Content-Type: application/json' \
  -d '{"version":"4","receiver":"ipsec-recovery","status":"firing","alerts":[{"status":"firing","labels":{"alertname":"ExampleIPsecTunnelMissing","peer":"example-partner"},"fingerprint":"test-1"}]}'
pytest -q
```

## Deployment

The same versioned wheel installs `ipsec-recovery-controller` and `ipsec-recovery-agent`. Run either executable independently; the agent is installed only on gateways that use the HTTPS transport. Existing SSH-only deployments keep their v0.2.0 configuration. See [operations](docs/operations.md), [architecture](docs/architecture.md), [security](docs/security.md), and `packaging/systemd/`.

Example files: `config.example.yaml` (SSH), `config.controller-agent.example.yaml`, and `config.agent.example.yaml`. Install only from a trusted, pinned release artifact with verified SHA256 digest.

## Safety

Keep production YAML, credentials, and SSH keys outside the public repository. Loopback-only access is required by default. Existing Alertmanager routes should not be replaced.

## License

Apache License 2.0. See LICENSE.


For root-only legacy stroke sockets, use the optional fixed-operation [privileged diagnostics helper](docs/privileged-diagnostics.md). The HTTPS agent stays unprivileged and can retain the direct backend where permissions allow.
