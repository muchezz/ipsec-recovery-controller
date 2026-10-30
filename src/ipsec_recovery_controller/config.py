from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerConfig(StrictModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)


class Gateway(StrictModel):
    host: str
    ssh_user: str = "ipsec-controller"
    adapter: Literal["auto", "legacy_ipsec", "swanctl"] = "auto"


class Connection(StrictModel):
    gateway: str
    ike_connection: str
    child_connection: str
    recovery_enabled: bool = False


class AlertRule(StrictModel):
    name: str
    connection: str


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
        if len({rule.name for rule in self.alerts}) != len(self.alerts):
            raise ValueError("alert names must be unique")


def load_config(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("configuration must be a YAML mapping")
    config = Config.model_validate(raw)
    # Inject secret from environment, never store it in a public configuration.
    token = os.getenv("IPSEC_CONTROLLER_WEBHOOK_TOKEN")
    if token:
        config.webhook_token = token
    config.validate_mappings()
    return config
