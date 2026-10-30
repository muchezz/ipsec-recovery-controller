from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, field_validator

from ipsec_recovery_controller.config import Connection, ServerConfig, StrictModel


class AgentConnection(StrictModel):
    ike_connection: str
    child_connection: str
    local_selector: str | None = None
    remote_selector: str | None = None

    def expected(self) -> Connection:
        return Connection(gateway="local", **self.model_dump())


class AgentConfig(StrictModel):
    server: ServerConfig = Field(default_factory=lambda: ServerConfig(host="127.0.0.1", port=8766))
    server_cert: str
    server_key: str
    client_ca: str
    allowed_client_identity: str
    inspection_backend: Literal["direct", "helper"] = "direct"
    helper_socket: str = "/run/ipsec-recovery-helper.sock"
    helper_timeout_seconds: float = Field(default=15, gt=0, le=120)
    ipsec_binary: str = "/usr/sbin/ipsec"
    command_timeout_seconds: float = Field(default=10, gt=0, le=120)
    connections: dict[str, AgentConnection] = Field(default_factory=dict)

    @field_validator("server_cert", "server_key", "client_ca", "ipsec_binary", "helper_socket")
    @classmethod
    def absolute_path(cls, value: str) -> str:
        if not Path(value).is_absolute():
            raise ValueError("agent file paths must be absolute")
        return value

    @field_validator("allowed_client_identity")
    @classmethod
    def nonempty_identity(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("client identity is required")
        return value

    def validate_mappings(self) -> None:
        for identifier in self.connections:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", identifier):
                raise ValueError("agent connection IDs must be URL-safe")
        targets = [tuple(connection.model_dump().values()) for connection in self.connections.values()]
        if len(targets) != len(set(targets)):
            raise ValueError("duplicate local connection mapping")


def load_agent_config(path: str | Path) -> AgentConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError("agent configuration must be a YAML mapping")
    config = AgentConfig.model_validate(raw)
    config.validate_mappings()
    return config
