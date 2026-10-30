from __future__ import annotations

import hmac
import json
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, ValidationError
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from starlette.responses import Response

from ipsec_recovery_controller.config import Config

log = logging.getLogger(__name__)
WEBHOOKS = Counter(
    "ipsec_controller_webhooks_total",
    "Alertmanager webhook events by outcome",
    ["outcome"],
)
DECISIONS = Counter(
    "ipsec_controller_decisions_total",
    "Read-only alert evaluation decisions",
    ["decision", "connection"],
)


class Alert(BaseModel):
    model_config = ConfigDict(extra="ignore")
    status: str
    labels: dict[str, str]
    fingerprint: str | None = None


class Webhook(BaseModel):
    model_config = ConfigDict(extra="ignore")
    version: str
    status: str
    receiver: str
    alerts: list[Alert]


def evaluate(config: Config, payload: Webhook) -> list[dict[str, str]]:
    mapping = {rule.name: rule.connection for rule in config.alerts}
    decisions: list[dict[str, str]] = []
    for alert in payload.alerts:
        name = alert.labels.get("alertname", "")
        connection = mapping.get(name)
        if not connection:
            decision = "unmapped"
            connection_label = "unmapped"
        elif alert.status != "firing" or payload.status != "firing":
            decision = "not_firing"
            connection_label = connection
        else:
            # Phase 1 deliberately does not connect to SSH or execute recovery.
            decision = "observed" if config.mode == "observe" else "inspection_not_implemented"
            connection_label = connection
        DECISIONS.labels(decision=decision, connection=connection_label).inc()
        log.info(
            "audit_event %s",
            json.dumps({
                "event": "alert_evaluated",
                "alertname": name,
                "fingerprint": alert.fingerprint,
                "connection": connection_label,
                "decision": decision,
                "mode": config.mode,
            }, sort_keys=True),
        )
        decisions.append({"alertname": name, "connection": connection_label, "decision": decision})
    return decisions


def create_app(config: Config) -> FastAPI:
    app = FastAPI(title="IPsec Recovery Controller", version="0.1.0", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "mode": config.mode}

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.post("/alerts")
    async def alerts(request: Request) -> dict[str, Any]:
        if config.webhook_token:
            supplied = request.headers.get("X-IPsec-Controller-Token", "")
            if not hmac.compare_digest(supplied, config.webhook_token):
                WEBHOOKS.labels(outcome="unauthorized").inc()
                raise HTTPException(status_code=401, detail="unauthorized")
        if request.headers.get("content-length"):
            try:
                if int(request.headers["content-length"]) > config.max_payload_bytes:
                    raise HTTPException(status_code=413, detail="payload too large")
            except ValueError:
                raise HTTPException(status_code=400, detail="invalid content-length")
        body = await request.body()
        if len(body) > config.max_payload_bytes:
            raise HTTPException(status_code=413, detail="payload too large")
        try:
            payload = Webhook.model_validate_json(body)
        except ValidationError:
            WEBHOOKS.labels(outcome="invalid").inc()
            raise HTTPException(status_code=422, detail="invalid Alertmanager webhook") from None
        if payload.version != "4":
            WEBHOOKS.labels(outcome="invalid_version").inc()
            raise HTTPException(status_code=422, detail="unsupported Alertmanager webhook version")
        decisions = evaluate(config, payload)
        WEBHOOKS.labels(outcome="accepted").inc()
        return {"mode": config.mode, "decisions": decisions, "recovery_executed": False}

    return app
