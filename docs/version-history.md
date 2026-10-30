# Version history

## 0.3.0 (development)

Adds a separately runnable gateway-local HTTPS agent, mTLS transport selection, local strongSwan status inspection, connection allowlists, independent systemd service, and a versioned `/v1` agent API. The package remains read-only and supports the v0.2.0 SSH configuration format. Agent API major versions must match; the controller rejects an incompatible response. A v0.3 controller requires a v0.3 agent for agent transport.

## 0.2.0

Read-only Alertmanager controller, SSH legacy strongSwan inspection, normalized diagnostics, audit logs, metrics, `observe` and `dry-run` modes.
