from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerConfig(StrictModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)


class AgentEndpoint(StrictModel):
    url: str
    ca_file: str
    client_cert: str
    client_key: str
    connect_timeout_seconds: float = Field(default=3, gt=0, le=60)
    request_timeout_seconds: float = Field(default=10, gt=0, le=120)
    max_response_bytes: int = Field(default=2_000_000, ge=1024, le=10_000_000)

    @field_validator("url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or not parsed.port
                or parsed.username or parsed.password or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment):
            raise ValueError("agent URL must be an HTTPS origin with an explicit port")
        return value.rstrip("/")

    @field_validator("ca_file", "client_cert", "client_key")
    @classmethod
    def absolute_path(cls, value: str) -> str:
        if not Path(value).is_absolute():
            raise ValueError("TLS paths must be absolute")
        return value


class Gateway(StrictModel):
    host: str | None = None
    transport: Literal["ssh", "agent"] = "ssh"
    agent: AgentEndpoint | None = None
    ssh_user: str = "ipsec-controller"
    adapter: Literal["auto", "legacy_ipsec", "swanctl"] = "auto"
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_identity_file: str | None = None
    ssh_known_hosts_file: str | None = None
    ssh_timeout_seconds: int = Field(default=10, ge=1, le=60)

    @model_validator(mode="after")
    def valid_transport(self) -> Gateway:
        if self.transport == "ssh" and not self.host:
            raise ValueError("SSH gateway requires host")
        if self.transport == "agent" and self.agent is None:
            raise ValueError("agent gateway requires agent configuration")
        return self

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
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
            if (self.gateways[connection.gateway].transport == "agent" and
                    not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name)):
                raise ValueError("agent connection IDs must be URL-safe")
        for rule in self.alerts:
            if rule.connection not in self.connections:
                raise ValueError(f"alert {rule.name!r} references unknown connection")
        identities = [(rule.name, tuple(sorted(rule.match_labels.items()))) for rule in self.alerts]
        if len(set(identities)) != len(identities):
            raise ValueError("alert name and label match must be unique")
        targets: set[tuple[str, str, str, str | None, str | None]] = set()
        for connection in self.connections.values():
            target = (connection.gateway, connection.ike_connection, connection.child_connection,
                      connection.local_selector, connection.remote_selector)
            if target in targets:
                raise ValueError("duplicate gateway/connection mapping")
            targets.add(target)


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
