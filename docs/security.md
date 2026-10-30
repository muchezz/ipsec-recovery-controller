# Security

- Bind to 127.0.0.1 by default; never expose the webhook directly to the Internet.
- Optionally require `X-IPsec-Controller-Token`, provided via `IPSEC_CONTROLLER_WEBHOOK_TOKEN`.
- Alert labels are data, never shell arguments.
- Strict configuration and allowlisted alert mappings.
- No privileged commands exist in v0.1.0.
- Do not commit real gateway addresses, credentials, tokens, or internal alert payloads.
- Metrics are unauthenticated: keep the listener on loopback.
- Future releases must implement restricted SSH, state verification, durable deduplication, and cooldowns before recovery mode.
