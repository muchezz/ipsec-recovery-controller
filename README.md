# IPsec Recovery Controller

A small, safe Alertmanager webhook controller for strongSwan IPsec recovery workflows.

**v0.1.0 is read-only.** It validates Alertmanager v4 webhooks, maps alert names to configured connections, records structured audit decisions, and exposes Prometheus metrics. `dry-run` does **not** simulate live SA inspection yet: it reports `inspection_not_implemented`. No SSH or recovery functionality is included.

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
  -d '{"version":"4","receiver":"ipsec-recovery","status":"firing","alerts":[{"status":"firing","labels":{"alertname":"ExampleIPsecTunnelMissing"},"fingerprint":"test-1"}]}'
pytest -q
```

## Deployment

See `packaging/systemd/` and `docs/operations.md`. Install only from a trusted, pinned release artifact with verified SHA256 digest. The release workflow currently uploads build artifacts to GitHub Actions; it does not publish a GitHub Release automatically. Do not point production at an unverified GitHub tag.

## Safety

Keep production YAML, credentials, and SSH keys outside the public repository. Loopback-only access is required by default. Existing Alertmanager routes should not be replaced.

## License

Apache License 2.0. See LICENSE.
