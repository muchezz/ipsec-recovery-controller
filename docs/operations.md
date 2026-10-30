# Operations

Install in a virtual environment and run `ipsec-recovery-controller` with `IPSEC_CONTROLLER_CONFIG` set.
Check `curl -fsS http://127.0.0.1:8765/healthz` and `curl -fsS http://127.0.0.1:8765/metrics`.
Use `journalctl -u ipsec-recovery-controller -f` for audit events.
Do not enable the Alertmanager receiver until local webhook tests pass.
Verify existing Alertmanager routes before enabling this receiver.
For each gateway, provision a read-only SSH account able to run `ipsec statusall`. Pin its host key in a known-hosts file readable by the service user. Set `ssh_identity_file` and `ssh_known_hosts_file` to absolute paths. Test host key verification and `ipsec statusall` as the service user before enabling Alertmanager routing. `auto` currently selects the legacy adapter; `swanctl` is not implemented.

In `observe`, firing mapped alerts return `observed` with no SSH access. In `dry-run`, they return `installed_unverified`, `ike_negotiating`, `child_negotiating`, `ike_missing`, `child_missing`, `unconfigured`, `unknown`, or `inspection_failed`. The response includes SA counts for successful inspections. An SA observation does not verify packet delivery. Check gateway output and connection names before acting manually. No recovery is possible in this release.

For repeated alert names, add `match_labels` to each rule and map each rule to a configured connection. Avoid overlapping match sets; ambiguous alerts are reported without inspection. A standby gateway should have its own connection entry and label match. Missing SAs on a standby gateway are observations only; this release has no active/standby policy.
