# Operations

Install in a virtual environment and run `ipsec-recovery-controller` with `IPSEC_CONTROLLER_CONFIG` set.
Check `curl -fsS http://127.0.0.1:8765/healthz` and `curl -fsS http://127.0.0.1:8765/metrics`.
Use `journalctl -u ipsec-recovery-controller -f` for audit events.
Do not enable the Alertmanager receiver until local webhook tests pass.
Verify existing Alertmanager routes before enabling this receiver.
For each gateway, provision a read-only SSH account able to run `ipsec statusall`. Pin its host key in a known-hosts file readable by the service user. Set `ssh_identity_file` and `ssh_known_hosts_file` to absolute paths. Test host key verification and `ipsec statusall` as the service user before enabling Alertmanager routing. `auto` currently selects the legacy adapter; `swanctl` is not implemented.

In `observe`, firing mapped alerts return `observed` with no SSH access. In `dry-run`, they return `installed_unverified`, `ike_negotiating`, `child_negotiating`, `ike_missing`, `child_missing`, `unconfigured`, `unknown`, or `inspection_failed`. The response includes SA counts for successful inspections. An SA observation does not verify packet delivery. Check gateway output and connection names before acting manually. No recovery is possible in this release.

For repeated alert names, add `match_labels` to each rule and map each rule to a configured connection. Avoid overlapping match sets; ambiguous alerts are reported without inspection. A standby gateway should have its own connection entry and label match. Missing SAs on a standby gateway are observations only; this release has no active/standby policy.

## Installing the two roles

Build one versioned wheel with `python -m build`. Copy the wheel to each target host, verify its SHA256 digest, and install it into a dedicated virtual environment (`python -m pip install /path/to/ipsec_recovery_controller-0.3.0-py3-none-any.whl`). The wheel contains both entry points, but each host runs only its assigned service. A controller-only host runs `IPSEC_CONTROLLER_CONFIG=/etc/ipsec-recovery-controller/config.yaml ipsec-recovery-controller`. An agent-only gateway runs `IPSEC_AGENT_CONFIG=/etc/ipsec-recovery-agent/config.yaml ipsec-recovery-agent`. For a single-host test, use separate configurations and ports and run both commands in separate terminals. For multiple gateways, deploy one agent per gateway and add one `transport: agent` gateway entry per endpoint. SSH-only installations can keep `config.example.yaml` and need no agent.

The sample systemd units in `packaging/systemd/` use separate unprivileged accounts, configuration paths, and virtual environments. Install only the relevant unit on each host. Set key and configuration file permissions for the service account and test the command as that account before enabling the unit. The agent account needs diagnostic access to local strongSwan state; grant only a socket ACL or group membership if `ipsec statusall` requires it. Do not grant recovery command privileges. Provision management routing and firewall rules separately; this repository does not change them.

## mTLS provisioning

Use your organization's CA workflow to issue an agent server certificate with a DNS or IP SAN matching the configured `agent.url`, and a controller client certificate with the identity configured as `allowed_client_identity` on each agent. Give the server certificate server authentication usage and the client certificate client authentication usage. Configure `server_cert`, `server_key`, and `client_ca` on each gateway; configure `ca_file`, `client_cert`, and `client_key` on the controller. Trust only the intended CA, protect keys outside the repository, and rotate before expiry. The CA private key stays offline. No production certificate material belongs in the public codebase.

`GET /v1/healthz`, `GET /v1/associations`, and `GET /v1/connections/{connection_id}` all require mTLS. The connection ID must appear in the agent's local `connections` mapping and match the controller's IKE, CHILD, and optional selector mapping. The controller still evaluates the normalized snapshot with its existing diagnostic engine. An unreachable agent returns `inspection_failed`; investigate network and certificate errors manually. It never initiates a tunnel operation.

The agent API is versioned at `/v1`. A controller using agent transport requires a compatible `/v1` agent and rejects an incompatible response. Pin controller and agent to the same package version for deployment. The central webhook remains `/alerts` and the metrics endpoint remains `/metrics`.


Agent service hardening: keep configuration and TLS files outside service-writable state directories. Use root-owned configuration directories (0750) and key/config files (0640, group ipsec-agent), with no service-account write access. Ensure configured paths remain accessible with ProtectHome and ProtectSystem enabled. Test diagnostic access as the service account; do not add sudo or capabilities to work around permission errors. AF_UNIX remains available for the strongSwan socket and AF_INET/AF_INET6 for HTTPS. The unit retries failures up to five times per minute; configuration or certificate startup failures remain visible in the journal. Correct the files, then reset the failed unit and restart. StrongSwan availability is checked on demand; agent health indicates HTTPS service availability, not tunnel health. Validate the unit against the target distribution's systemd version before enabling it.


For root-only legacy stroke sockets, use the optional fixed-operation [privileged diagnostics helper](privileged-diagnostics.md). The HTTPS agent stays unprivileged and can retain the direct backend where permissions allow.
