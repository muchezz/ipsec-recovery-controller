"""Strict parser for the read-only legacy strongSwan statusall output."""

from __future__ import annotations

import re
from dataclasses import replace

from ipsec_recovery_controller.config import Gateway
from ipsec_recovery_controller.diagnostics.models import Association, GatewaySnapshot
from ipsec_recovery_controller.gateway.ssh import GatewayTransport, InspectionError

_HEADER = re.compile(r"^Security Associations \((\d+) up, (\d+) connecting\):$")
_SA = re.compile(r"^\s*([^\s\[\]{}:]+)(?:\[(\d+)\]|\{(\d+)\}):\s*(.*)$")
_CONNECTION = re.compile(r"^\s*([^\s\[\]{}:]+):\s+.+$")
_IKE_STATES = {"ESTABLISHED", "CONNECTING", "CREATED", "REKEYING", "DELETING"}
_CHILD_STATES = {"INSTALLED", "CREATED", "REKEYING", "ROUTED", "DELETING"}
_STATE = re.compile(r"^(ESTABLISHED|CONNECTING|CREATED|REKEYING|DELETING|INSTALLED|ROUTED)\b")
_COUNTER = re.compile(r"\b(\d+) bytes_([io])\b")
_PACKETS = re.compile(r"\b\d+ bytes_([io])\s+\((\d+) pkts?\b")
_SPI = re.compile(r"\b(?:IKE(?:v[12])?|ESP(?: in UDP)?) SPIs?:\s*([^,]+)")


def parse_status(output: str, source: str = "ipsec statusall") -> GatewaySnapshot:
    if not output.endswith("\n"):
        raise InspectionError("malformed_output", "status output is truncated")
    section = ""
    header: tuple[int, int] | None = None
    connections_seen = False
    connections: set[str] = set()
    ikes: list[Association] = []
    children: list[Association] = []
    current_ike: str | None = None
    last_sa: tuple[str, int] | None = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "Connections:":
            if header is not None:
                raise InspectionError("malformed_output", "Connections section follows SAs")
            section = "connections"
            connections_seen = True
            continue
        if stripped.startswith("Security Associations"):
            match = _HEADER.fullmatch(stripped)
            if not match or header is not None:
                raise InspectionError("malformed_output", "invalid SA section header")
            header = (int(match[1]), int(match[2]))
            section = "sas"
            last_sa = None
            continue
        if stripped in {"Routed Connections:", "Shunted Connections:"}:
            if header is not None:
                raise InspectionError("malformed_output")
            section = "other"
            continue
        if section == "sas":
            if stripped == "none" and header == (0, 0) and not ikes and not children:
                continue
            match = _SA.match(line)
            if match:
                name, ike_id, child_id, body = match.groups()
                kind, identifier = ("[", ike_id) if ike_id is not None else ("{", child_id)
                if not body:
                    raise InspectionError("malformed_output", "empty association record")
                state = _STATE.search(body)
                if state:
                    valid = _IKE_STATES if kind == "[" else _CHILD_STATES
                    if state[1] not in valid:
                        raise InspectionError("malformed_output", "invalid SA state")
                    records = ikes if kind == "[" else children
                    if any(sa.identifier == identifier for sa in records):
                        raise InspectionError("malformed_output", "duplicate association ID")
                    association = Association(
                        name, identifier, state[1],
                        parent_ike_id=current_ike if kind == "{" else None,
                        spi=(spi_match[1].strip() if (spi_match := _SPI.search(body)) else None),
                    )
                    if kind == "[":
                        current_ike = identifier
                        ikes.append(association)
                        last_sa = ("ike", len(ikes) - 1)
                    else:
                        children.append(association)
                        last_sa = ("child", len(children) - 1)
                elif last_sa is not None:
                    target = ikes if last_sa[0] == "ike" else children
                    previous = target[last_sa[1]]
                    if name != previous.name or identifier != previous.identifier or (
                        (kind == "[") != (last_sa[0] == "ike")
                    ):
                        raise InspectionError("malformed_output", "orphaned SA detail")
                    spi_match = _SPI.search(body)
                    counters = {direction: int(value) for value, direction in _COUNTER.findall(body)}
                    packets = {direction: int(value) for direction, value in _PACKETS.findall(body)}
                    selectors = body.split("===", 1) if "===" in body else None
                    if selectors and not all(value.strip() for value in selectors):
                        raise InspectionError("malformed_output", "incomplete selectors")
                    target[last_sa[1]] = replace(
                        previous,
                        spi=spi_match[1].strip() if spi_match else previous.spi,
                        local_selector=selectors[0].strip() if selectors else previous.local_selector,
                        remote_selector=selectors[1].strip() if selectors else previous.remote_selector,
                        bytes_in=counters.get("i", previous.bytes_in),
                        bytes_out=counters.get("o", previous.bytes_out),
                        packets_in=packets.get("i", previous.packets_in),
                        packets_out=packets.get("o", previous.packets_out),
                    )
                else:
                    raise InspectionError("malformed_output", "SA detail has no parent")
            elif stripped:
                raise InspectionError("malformed_output", "malformed SA entry")
        elif section == "connections":
            match = _CONNECTION.match(line)
            if match:
                connections.add(match[1])
    if header is None:
        raise InspectionError("malformed_output", "SA section is missing")
    up = sum(sa.state == "ESTABLISHED" for sa in ikes)
    connecting = sum(sa.state in {"CONNECTING", "CREATED"} for sa in ikes)
    if (up, connecting) != header:
        raise InspectionError("malformed_output", "SA count differs from section header")
    return GatewaySnapshot(
        frozenset(connections), tuple(ikes), tuple(children), source, connections_seen,
    )


class LegacyIPsecAdapter:
    def __init__(self, transport: GatewayTransport):
        self.transport = transport

    def inspect(self, gateway: Gateway) -> GatewaySnapshot:
        return parse_status(self.transport.run(gateway, "ipsec statusall"))
