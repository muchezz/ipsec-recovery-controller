"""Evaluate expected connection state without changing the gateway."""

from __future__ import annotations

from ipsec_recovery_controller.adapters.legacy_ipsec import LegacyIPsecAdapter
from ipsec_recovery_controller.config import Config, Connection
from ipsec_recovery_controller.diagnostics.models import Diagnostic, GatewaySnapshot
from ipsec_recovery_controller.gateway.https_agent import HTTPSAgentTransport
from ipsec_recovery_controller.gateway.ssh import GatewayTransport, InspectionError, SSHTransport


def evaluate_snapshot(connection: Connection, snapshot: GatewaySnapshot) -> Diagnostic:
    ike = [sa for sa in snapshot.ike_sas if sa.name == connection.ike_connection]
    named_children = [sa for sa in snapshot.child_sas if sa.name == connection.child_connection]
    children = [
        sa for sa in named_children
        if (connection.local_selector is None or sa.local_selector == connection.local_selector)
        and (connection.remote_selector is None or sa.remote_selector == connection.remote_selector)
    ]
    selector_evidence_missing = bool(named_children) and bool(
        connection.local_selector or connection.remote_selector
    ) and any(
        (connection.local_selector is not None and sa.local_selector is None)
        or (connection.remote_selector is not None and sa.remote_selector is None)
        for sa in named_children
    )
    established = sum(sa.state == "ESTABLISHED" for sa in ike)
    ike_negotiating = sum(sa.state in {"CONNECTING", "CREATED", "REKEYING"} for sa in ike)
    installed = sum(sa.state == "INSTALLED" for sa in children)
    child_negotiating = sum(sa.state in {"CREATED", "REKEYING"} for sa in children)
    configured = (
        connection.ike_connection in snapshot.configured_connections
        if snapshot.connections_known else None
    )
    parents = {sa.identifier for sa in ike if sa.state == "ESTABLISHED"}
    installed_children = [sa for sa in children if sa.state == "INSTALLED"]
    if selector_evidence_missing:
        state = "unknown"
    elif configured is False:
        state = "unconfigured" if not ike and not children else "unknown"
    elif installed_children and (not established or any(sa.parent_ike_id not in parents for sa in installed_children)):
        state = "unknown"
    elif established and installed:
        state = "installed_unverified"
    elif ike_negotiating and not established:
        state = "ike_negotiating"
    elif not established and configured is True:
        state = "ike_missing"
    elif not established:
        state = "unknown"
    elif child_negotiating and not installed:
        state = "child_negotiating"
    elif configured is True:
        state = "child_missing"
    else:
        state = "unknown"
    return Diagnostic(
        state, configured, established, ike_negotiating, installed, child_negotiating,
        tuple(ike), tuple(children),
    )


class Inspector:
    def __init__(self, config: Config, transport: GatewayTransport | None = None):
        self.config = config
        self.transport = transport or SSHTransport()

    def inspect(self, connection_name: str) -> Diagnostic:
        connection = self.config.connections[connection_name]
        gateway = self.config.gateways[connection.gateway]
        if gateway.adapter == "swanctl":
            raise InspectionError("adapter_unavailable")
        if gateway.transport == "agent":
            snapshot = HTTPSAgentTransport().inspect(gateway, connection_name, connection)
            return evaluate_snapshot(connection, snapshot)
        snapshot = LegacyIPsecAdapter(self.transport).inspect(gateway)
        return evaluate_snapshot(connection, snapshot)
