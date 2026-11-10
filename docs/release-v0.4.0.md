# v0.4.0

Adds disabled-by-default, allowlisted CHILD_SA recovery after a validated `PakakobeIPsecTunnelMissing` alert. Existing observe/dry-run operation stays read-only, and PagerDuty/Mattermost routing stays unchanged.

Recovery requires controller webhook authentication, agent mTLS identity, independent controller/agent/helper allowlists, an enabled root-owned helper policy, live HA ownership and IKE/CHILD state checks, and exact strongSwan 5.8.2 configuration/selector evidence. The sole mutation is targeted connection initiation; no restart, down or reload operation is available.

Persistent admission provides deduplication across restarts, connection locks/cooldowns, one global recovery, storm protection, expiring requests, crash/timeout holds and post-recovery verification. An explicit offline state initializer refuses existing files; lost or corrupt state fails closed instead of silently resetting safety history.

Release validation includes 30 simultaneous webhook deliveries, repeated/restarted incidents, duplicate/negotiating SAs, helper timeouts, uncertain outcomes, wrong mappings/selectors, HA transitions, unsupported versions, state corruption and authentication failures. The full Python test suite, lint, compilation, dependency checks and byte-for-byte repeated package builds must pass before publication.

Isolated source-built 5.8.2 validation confirmed real loopback IKE authentication, targeted stroke selection, loaded selector output and missing-CHILD recognition. Outbound kernel SA installation was unavailable in the container, so successful CHILD recovery and traffic flow remain unvalidated; see `docs/validation-v0.4.0.md`.

Recovery supports a conservative subset: matching IKE/CHILD names and one canonical CIDR selector per side. Legacy stroke inspection and initiation are separate operations, so external negotiation/administrative races remain possible. HA ownership requires exclusive address fencing. Installation verification does not prove traffic flow. Validate the actual distribution package in staging before enabling recovery; this release does not deploy or activate anything.

See `docs/recovery-policy.md` and `docs/recovery-deployment.md`. Release assets include wheel, source distribution, build provenance and SHA256 checksums; build instructions are in `docs/releasing.md`.
