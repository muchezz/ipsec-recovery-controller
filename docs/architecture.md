# Architecture

Prometheus -> Alertmanager -> local HTTP webhook -> strict validation -> allowlisted alert mapping -> selected gateway transport (SSH or HTTPS agent) -> legacy strongSwan adapter -> normalized IKE/CHILD snapshot -> diagnostic decision -> audit + metrics.

The agent runs on each strongSwan gateway and calls a local, fixed `ipsec statusall` command. Its versioned `/v1` API exposes health, all associations, and locally authorized connection IDs. The controller and agent use independent configuration and service accounts. The controller verifies HTTPS server identity and presents a client certificate; the agent requires a CA-trusted client certificate and checks its configured identity. The agent returns its local mapping with each connection snapshot; the controller rejects a mismatch. Additional gateways use separate controller gateway entries and agent instances. The management network can be an existing private or IPsec network; routing and firewall access are deployment responsibilities.

The `auto` and `legacy_ipsec` adapter values select legacy `ipsec` inspection. `swanctl` is reserved and reports an inspection failure. The adapter protocol and normalized snapshot allow later swanctl/VICI adapters without changing alert evaluation.

`dry-run` issues only `ipsec statusall`; there is no automatic fallback after SSH or parse errors. The parser requires a complete SA header, reconciles its IKE counts, and rejects malformed entries or output lacking a final newline. It tracks configured connections, IKE SAs, and CHILD SAs separately, retaining IDs, parent relationships, selectors, SPIs, and available byte counters. Multiple CHILD SAs remain separate records. An established IKE and installed expected CHILD yield `installed_unverified`, since SA installation does not prove packet delivery. An installed CHILD under the wrong or missing IKE is `unknown`. Missing states require a parsed Connections section that confirms the connection is configured; otherwise the result is `unknown` or `unconfigured`.

Alert rules may share a name when `match_labels` explicitly selects different configured connections. Each connection names a gateway, IKE connection, and CHILD connection. Zero matching rules return `unmapped`; overlapping matches return `ambiguous_mapping` without inspecting a gateway. Alert labels are never used as SSH destinations or command arguments.

When legacy CHILD SAs share the same name, configure optional `local_selector` and `remote_selector` on separate connection entries to identify the expected association. If the gateway omits selectors needed for matching, the result is `unknown`.

No recovery policy runs in this release. `observe` validates, audits, and counts events without gateway contact. `dry-run` inspects. Agent outages, certificate failures, timeouts, mapping mismatches, and command errors fail closed as `inspection_failed` with a structured error code. They never trigger recovery.
The service is single-process. No queue or persistent deduplication is implemented yet.
The HTTP response means the event was evaluated in-process, not durably queued.
