# Architecture

Prometheus -> Alertmanager -> local HTTP webhook on kifaru -> strict validation -> allowlisted alert mapping -> audit + metrics.

Phase 1 is intentionally read-only: **no SSH, no SA inspection, no recovery commands**.
The `auto` adapter value is reserved for capability detection in Phase 2.
The service is single-process. No queue or persistent deduplication is implemented yet.
The HTTP response means the event was evaluated in-process, not durably queued.
