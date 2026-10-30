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
