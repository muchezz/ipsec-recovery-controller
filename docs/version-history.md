# Version history

## v0.4.0

Adds disabled-by-default targeted CHILD_SA initiation for a verified strongSwan 5.8.2 subset, independent helper authorization, live HA/state checks, durable admission controls, post-verification and audited outcomes. Observe/dry-run and existing routing remain unchanged. See recovery-policy.md for unsupported layouts and deployment limits.

## 0.3.0

Adds an optional socket-activated privileged statusall helper with Linux peer-UID authorization, independent units, and sanitized strongSwan 5.8.2 parser fixtures. Packet counters and UDP ESP SPIs are preserved.

Adds a separately runnable gateway-local HTTPS agent, mTLS transport selection, local strongSwan status inspection, connection allowlists, independent systemd service, and a versioned `/v1` agent API. The package remains read-only and supports the v0.2.0 SSH configuration format. Agent API major versions must match; the controller rejects an incompatible response. A v0.3 controller requires a v0.3 agent for agent transport.

## 0.2.0

Read-only Alertmanager controller, SSH legacy strongSwan inspection, normalized diagnostics, audit logs, metrics, `observe` and `dry-run` modes.
