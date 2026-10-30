# Operations

Install in a virtual environment and run `ipsec-recovery-controller` with `IPSEC_CONTROLLER_CONFIG` set.
Check `curl -fsS http://127.0.0.1:8765/healthz` and `curl -fsS http://127.0.0.1:8765/metrics`.
Use `journalctl -u ipsec-recovery-controller -f` for audit events.
Do not enable the Alertmanager receiver until local webhook tests pass.
Alertmanager's existing Mattermost and PagerDuty routes must be verified before enabling this route.
No recovery is possible in this release.
