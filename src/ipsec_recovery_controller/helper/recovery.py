"""Root-owned allowlist and strict strongSwan 5.8.2 initiation subset."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time

import yaml
from pydantic import Field, model_validator

from ipsec_recovery_controller.adapters.legacy_ipsec import parse_status
from ipsec_recovery_controller.config import Connection, RecoveryPolicy, StrictModel
from ipsec_recovery_controller.gateway.ssh import InspectionError
from ipsec_recovery_controller.recovery import RecoveryGate, mapping_hash


class Target(StrictModel):
    connection: Connection
    active_address: str

    @model_validator(mode="after")
    def safe_target(self):
        c = self.connection
        ipaddress.ip_address(self.active_address)
        if not c.recovery_enabled or c.ike_connection != c.child_connection:
            raise ValueError("recovery requires identical IKE/CHILD names and explicit enablement")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", c.child_connection):
            raise ValueError("unsafe connection name")
        for selector in (c.local_selector, c.remote_selector):
            if selector is None or str(ipaddress.ip_network(selector, strict=True)) != selector:
                raise ValueError("recovery requires canonical, single CIDR selectors")
        return self


class HelperRecoveryConfig(StrictModel):
    enabled: bool = False
    policy: RecoveryPolicy = Field(default_factory=lambda: RecoveryPolicy(
        state_directory="/var/lib/ipsec-recovery-helper"))
    targets: dict[str, Target] = Field(default_factory=dict)

    @model_validator(mode="after")
    def unique_names(self):
        names = [t.connection.child_connection for t in self.targets.values()]
        if len(names) != len(set(names)):
            raise ValueError("recovery command names must be unique")
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key)
               for key in self.targets):
            raise ValueError("unsafe connection ID")
        return self


def load_policy(path: str) -> HelperRecoveryConfig:
    # Also protect parent directories, scripts and dependencies at deployment.
    with open(path, encoding="utf-8") as stream:
        stat = os.fstat(stream.fileno())
        if stat.st_uid != 0 or stat.st_mode & 0o022:
            raise ValueError("helper policy must be root-owned and not group/world writable")
        return HelperRecoveryConfig.model_validate(yaml.safe_load(stream))


def validate_live(output: str, target: Target, installed: bool = False):
    c = target.connection
    if not re.match(r"^Status of IKE charon daemon \(strongSwan 5\.8\.2,", output):
        raise InspectionError("recovery_version_unverified")
    snapshot = parse_status(output)
    # Verify loaded config, not alert labels or only a configuration-file assertion.
    if not snapshot.connections_known or c.ike_connection not in snapshot.configured_connections:
        raise InspectionError("recovery_unconfigured")
    if "Routed Connections:" in output or "Shunted Connections:" in output:
        raise InspectionError("recovery_routed_ambiguous")
    section = output.split("Connections:\n", 1)[1].split("Security Associations", 1)[0]
    rows = [line.split(":", 1)[1].strip() for line in section.splitlines()
            if line.split(":", 1)[0].strip() == c.child_connection]
    peers = [row for row in rows if re.fullmatch(r"\S+\.\.\.\S+\s+IKEv2(?:, dpddelay=\d+s)?", row)]
    selectors = [row for row in rows if "===" in row]
    expected = f"child:  {c.local_selector} === {c.remote_selector} TUNNEL"
    normalized = [re.sub(r", dpdaction=(?:none|clear|hold|restart)$", "", row)
                  for row in selectors]
    if len(peers) != 1 or normalized != [expected]:
        raise InspectionError("recovery_selectors_unverified")
    parent_name = None
    for line in section.splitlines():
        if ":" not in line:
            continue
        name, body = line.split(":", 1)
        if re.match(r"\s*\S+\.\.\.\S+\s+IKEv[12]", body):
            parent_name = name.strip()
        if (name.strip() == c.child_connection and "child:" in body
                and parent_name != c.ike_connection):
            raise InspectionError("recovery_configuration_ambiguous")
    ikes = [sa for sa in snapshot.ike_sas if sa.name == c.ike_connection]
    if len(ikes) != 1 or ikes[0].state != "ESTABLISHED":
        raise InspectionError("recovery_ike_ambiguous")
    # Block name collisions, any child under this parent, and selector collisions
    # under other parents. Legacy stroke cannot safely disambiguate these layouts.
    children = [sa for sa in snapshot.child_sas if (
        sa.name == c.child_connection or sa.parent_ike_id == ikes[0].identifier
        or (sa.local_selector == c.local_selector and sa.remote_selector == c.remote_selector)
    )]
    if not installed and children:
        raise InspectionError("recovery_child_present")
    if installed and (len(children) != 1 or children[0].name != c.child_connection
                      or children[0].state != "INSTALLED"
                      or children[0].parent_ike_id != ikes[0].identifier
                      or children[0].local_selector != c.local_selector
                      or children[0].remote_selector != c.remote_selector):
        raise InspectionError("recovery_verification_failed")
    if re.search(r"\]: Tasks (?:queued|active|passive):", output):
        raise InspectionError("recovery_tasks_pending")
    return ikes[0].identifier


def recover(config: HelperRecoveryConfig, identifier: str, event: str, mapping: str, expires: int) -> str:
    from ipsec_recovery_controller.helper import server

    if not config.enabled or identifier not in config.targets:
        raise InspectionError("recovery_not_allowed")
    target = config.targets[identifier]
    if mapping_hash(target.connection) != mapping:
        raise InspectionError("recovery_mapping_mismatch")

    def active():
        data = json.loads(server.command(["/usr/sbin/ip", "-j", "address", "show"]))
        addresses = [entry for interface in data if "UP" in interface["flags"]
                     for entry in interface["addr_info"]
                     if entry["local"] == target.active_address
                     and type(entry["preferred_life_time"]) is int
                     and entry["preferred_life_time"] > 0
                     and not entry.get("tentative", False)
                     and not entry.get("dadfailed", False)]
        if len(addresses) != 1:
            raise InspectionError("recovery_gateway_not_active")

    def deadline():
        if not time.time() < expires <= time.time() + 60:
            raise InspectionError("recovery_request_expired")

    def operation():
        deadline()
        active()
        parent = validate_live(server.statusall(), target)
        # No inspection network round trip occurs between this ownership check and up.
        active()
        deadline()
        server.command(["/usr/sbin/ipsec", "up", target.connection.child_connection])
        active()
        if validate_live(server.statusall(), target, installed=True) != parent:
            raise InspectionError("recovery_parent_changed")
        return "recovered"

    return RecoveryGate(config.policy).run(identifier, event, operation)
