from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class Association:
    name: str
    identifier: str
    state: str
    parent_ike_id: str | None = None
    spi: str | None = None
    local_selector: str | None = None
    remote_selector: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None


@dataclass(frozen=True)
class GatewaySnapshot:
    configured_connections: frozenset[str] = frozenset()
    ike_sas: tuple[Association, ...] = ()
    child_sas: tuple[Association, ...] = ()
    source: str = ""
    connections_known: bool = False


@dataclass(frozen=True)
class Diagnostic:
    state: Literal["installed_unverified", "ike_negotiating", "child_negotiating", "ike_missing", "child_missing", "unconfigured", "unknown"]
    configured: bool | None
    ike_established: int
    ike_negotiating: int
    child_installed: int
    child_negotiating: int
    ike_sas: tuple[Association, ...] = ()
    child_sas: tuple[Association, ...] = ()
    details: dict[str, str] = field(default_factory=dict)
