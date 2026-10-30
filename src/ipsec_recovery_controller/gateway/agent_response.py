"""Validate the complete v1 wire contract before diagnostic evaluation."""
from __future__ import annotations

import json
from dataclasses import fields

from fastapi.encoders import jsonable_encoder
from pydantic import TypeAdapter

from ipsec_recovery_controller.config import Connection
from ipsec_recovery_controller.diagnostics.models import Association, GatewaySnapshot
from ipsec_recovery_controller.gateway.ssh import InspectionError


def validate_response(data: object, expected: Connection) -> GatewaySnapshot:
    if not isinstance(data, dict):
        raise TypeError("response must be an object")
    if data.get("api_version") != "v1":
        raise InspectionError("agent_api_incompatible")
    if set(data) != {"api_version", "mapping", "snapshot", "diagnostic"}:
        raise ValueError("incomplete response")
    mapping = data["mapping"]
    required = {"ike_connection", "child_connection", "local_selector", "remote_selector"}
    if not isinstance(mapping, dict) or set(mapping) != required:
        raise ValueError("incomplete mapping")
    if mapping != {field: getattr(expected, field) for field in required}:
        raise InspectionError("agent_mapping_mismatch")
    raw = data["snapshot"]
    if not isinstance(raw, dict) or set(raw) != {field.name for field in fields(GatewaySnapshot)}:
        raise ValueError("incomplete snapshot")
    for kind in ("ike_sas", "child_sas"):
        if not isinstance(raw[kind], list):
            raise TypeError("associations must be arrays")
        for sa in raw[kind]:
            if not isinstance(sa, dict) or set(sa) != {field.name for field in fields(Association)}:
                raise ValueError("incomplete association")
    snapshot = TypeAdapter(GatewaySnapshot).validate_json(json.dumps(raw), strict=True)
    if snapshot.source != "ipsec statusall":
        raise ValueError("unsupported snapshot source")
    if snapshot.configured_connections - {expected.ike_connection}:
        raise ValueError("unauthorized configured connection")
    parents = {sa.identifier for sa in snapshot.ike_sas}
    for associations, name, states in (
        (snapshot.ike_sas, expected.ike_connection,
         {"ESTABLISHED", "CONNECTING", "CREATED", "REKEYING", "DELETING"}),
        (snapshot.child_sas, expected.child_connection,
         {"INSTALLED", "CREATED", "REKEYING", "ROUTED", "DELETING"}),
    ):
        identifiers = [sa.identifier for sa in associations]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("duplicate association")
        for sa in associations:
            if sa.name != name or sa.state not in states or not sa.identifier.isdecimal():
                raise ValueError("invalid association")
            if any(value is not None and value < 0 for value in (sa.bytes_in, sa.bytes_out)):
                raise ValueError("negative counter")
    if any(sa.parent_ike_id is not None for sa in snapshot.ike_sas):
        raise ValueError("invalid IKE parent")
    for sa in snapshot.child_sas:
        if sa.parent_ike_id not in parents:
            raise ValueError("orphaned CHILD")
        for field in ("local_selector", "remote_selector"):
            if getattr(expected, field) is not None and getattr(sa, field) != getattr(expected, field):
                raise ValueError("selector mismatch")
    from ipsec_recovery_controller.diagnostics.inspection import evaluate_snapshot

    diagnostic = jsonable_encoder(evaluate_snapshot(expected, snapshot))
    if json.dumps(data["diagnostic"], sort_keys=True) != json.dumps(diagnostic, sort_keys=True):
        raise ValueError("inconsistent diagnostic")
    return snapshot
