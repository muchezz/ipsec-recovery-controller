from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerConfig(StrictModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)


class Gateway(StrictModel):
    host: str
    ssh_user: str = "ipsec-controller"
    adapter: Literal["auto", "legacy_ipsec", "swanctl"] = "auto"
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_identity_file: str | None = None
    ssh_known_hosts_file: str | None = None
    ssh_timeout_seconds: int = Field(default=10, ge=1, le=60)

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value):
                raise ValueError("host must be an IP address or hostname") from None
        return value

    @field_validator("ssh_user")
    @classmethod
    def valid_user(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", value):
            raise ValueError("invalid SSH user")
        return value

    @field_validator("ssh_identity_file", "ssh_known_hosts_file")
    @classmethod
    def absolute_ssh_path(cls, value: str | None) -> str | None:
        if value is not None and not Path(value).is_absolute():
            raise ValueError("SSH file paths must be absolute")
        return value


class Connection(StrictModel):
    gateway: str
    ike_connection: str
    child_connection: str
    local_selector: str | None = None
    remote_selector: str | None = None
    recovery_enabled: bool = False


class AlertRule(StrictModel):
    name: str
    connection: str
    match_labels: dict[str, str] = Field(default_factory=dict)


class Config(StrictModel):
    mode: Literal["observe", "dry-run"] = "dry-run"
    server: ServerConfig = Field(default_factory=ServerConfig)
    gateways: dict[str, Gateway] = Field(default_factory=dict)
    connections: dict[str, Connection] = Field(default_factory=dict)
    alerts: list[AlertRule] = Field(default_factory=list)
    max_payload_bytes: int = Field(default=262144, ge=1024, le=1048576)
    webhook_token: str | None = None

    def validate_mappings(self) -> None:
        for name, connection in self.connections.items():
            if connection.gateway not in self.gateways:
                raise ValueError(f"connection {name!r} references unknown gateway")
        for rule in self.alerts:
            if rule.connection not in self.connections:
                raise ValueError(f"alert {rule.name!r} references unknown connection")
        identities = [(rule.name, tuple(sorted(rule.match_labels.items()))) for rule in self.alerts]
        if len(set(identities)) != len(identities):
            raise ValueError("alert name and label match must be unique")


def load_config(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError("configuration must be a YAML mapping")
    config = Config.model_validate(raw)
    # Inject secret from environment, never store it in a public configuration.
    token = os.getenv("IPSEC_CONTROLLER_WEBHOOK_TOKEN")
    if token:
        config.webhook_token = token
    config.validate_mappings()
    return config
