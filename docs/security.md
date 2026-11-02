# Security

- Bind to 127.0.0.1 by default; never expose the webhook directly to the Internet.
- Optionally require `X-IPsec-Controller-Token`, provided via `IPSEC_CONTROLLER_WEBHOOK_TOKEN`.
- Alert labels are data, never shell arguments.
- Strict configuration and allowlisted alert mappings.
- The SSH transport allows only fixed read-only commands, currently calling `ipsec statusall`. It uses argument arrays, BatchMode, strict host key checking, bounded output, and a timeout. Agent/X11 forwarding, port forwarding, proxy commands, and connection sharing are disabled.
- Restrict the remote account with a forced-command wrapper that accepts only the exact diagnostic command, or an equivalent server-side allowlist. Disable PTY and forwarding with `authorized_keys` restrictions and `sshd_config`. Grant only the minimum privileges needed for status inspection; do not grant `ipsec up`, `down`, `restart`, or general-purpose sudo access.
- Provision a pinned known-hosts file and a dedicated SSH identity outside the repository. Configure their absolute paths in gateway configuration. The default systemd unit's `ProtectHome=true` means files under the service user's home are inaccessible.
- Raw SSH output and stderr are not returned to webhook clients; inspection failures carry only a structured error code.
- Do not commit real gateway addresses, credentials, tokens, or internal alert payloads.
- Metrics are unauthenticated: keep the listener on loopback.
- Future releases need state verification, durable deduplication, and cooldowns before recovery mode.

## HTTPS agent

- The agent serves HTTPS with `CERT_REQUIRED` and a configured client CA. It checks the verified peer certificate identity against `allowed_client_identity`; request headers cannot assert that identity. Use a dedicated client identity and narrowly scoped CA. The controller verifies the agent certificate against `ca_file` and the exact hostname or IP in `agent.url`. For IP URLs, issue an IP Subject Alternative Name. Invalid, untrusted, and expired certificates fail closed.
- Provision server and client private keys outside the repository with ownership and mode permitting only the respective service account. Issue short-lived leaf certificates with appropriate server/client Extended Key Usage; rotate them before expiry. Keep the CA private key offline. Open only the required management address and port between authorized controller and gateway hosts. Existing management IPsec tunnels may carry this traffic but do not replace mTLS.
- The agent checks each requested connection ID against its local map. Both sides reject duplicate target mappings, and the controller rejects map disagreement. No shell commands are derived from HTTP input. Only `ipsec statusall` is used for inspection; `ipsec status` is allowlisted for future diagnostics but has no API route.
- Run the agent as an unprivileged account with read access to the strongSwan status/control socket if the distribution requires it. Verify `ipsec statusall` works as that account. Grant a narrowly scoped group membership or socket ACL if needed. Do not grant root, unrestricted sudo, or CAP_NET_ADMIN. The service unit clears capabilities and hardens filesystem access.
- Agent errors return codes, not raw command output. Gateway status data is sensitive: protect mTLS keys, logs, and access to the agent endpoint. The `/v1/healthz` endpoint also requires mTLS.


Agent snapshots are restricted to local connection mappings. `/v1/associations` returns the union of those mappings, including selector restrictions; `/v1/connections/{id}` returns only that mapping. There is no unrestricted inventory option. Missing selector evidence or an unexpected parent fails inspection rather than suggesting a missing tunnel. The controller requires every snapshot and association field, validates states, IDs, parents and counters, and checks diagnostic consistency before evaluating the snapshot.

The Uvicorn protocol binds the verified TLS certificate to a connection-specific application wrapper. The wrapper populates each request scope before invoking the application, including requests on persistent connections. It only accepts peer certificates from a TLS context configured with CERT_REQUIRED. Do not replace this protocol with a stock HTTP server or trust identity headers.

A strongSwan control socket may permit mutations as well as status inspection. Group or ACL access is therefore not necessarily a read-only operating-system permission. Audit the distribution's socket permissions; where that distinction is required, use a separately enforced diagnostic broker. The agent itself only executes allowlisted status commands and receives no root privileges or capabilities.


For root-only legacy stroke sockets, use the optional fixed-operation [privileged diagnostics helper](privileged-diagnostics.md). The HTTPS agent stays unprivileged and can retain the direct backend where permissions allow.
