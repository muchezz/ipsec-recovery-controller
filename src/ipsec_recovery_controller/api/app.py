from __future__ import annotations

import hmac
import json
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from ipsec_recovery_controller.config import Config
from ipsec_recovery_controller.diagnostics.inspection import Inspector
from ipsec_recovery_controller.gateway.ssh import InspectionError

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
DIAGNOSTICS = Counter(
    "ipsec_controller_diagnostics_total",
    "Read-only gateway inspections by observed state",
    ["state", "connection"],
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


def evaluate(config: Config, payload: Webhook, inspector: Inspector | None = None) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    if config.mode == "dry-run":
        inspector = inspector or Inspector(config)
    for alert in payload.alerts:
        name = alert.labels.get("alertname", "")
        matches = [
            rule for rule in config.alerts
            if rule.name == name and all(alert.labels.get(key) == value for key, value in rule.match_labels.items())
        ]
        connection = matches[0].connection if len(matches) == 1 else None
        error_code = None
        if len(matches) > 1:
            decision = "ambiguous_mapping"
            connection_label = "ambiguous"
            diagnostic = None
        elif not connection:
            decision = "unmapped"
            connection_label = "unmapped"
            diagnostic = None
        elif alert.status != "firing" or payload.status != "firing":
            decision = "not_firing"
            connection_label = connection
            diagnostic = None
        elif config.mode == "observe":
            decision = "observed"
            connection_label = connection
            diagnostic = None
        else:
            connection_label = connection
            try:
                assert inspector is not None
                diagnostic = inspector.inspect(connection)
                decision = diagnostic.state
                DIAGNOSTICS.labels(state=decision, connection=connection).inc()
            except InspectionError as exc:
                decision = "inspection_failed"
                error_code = exc.code
                diagnostic = None
                DIAGNOSTICS.labels(state="unknown", connection=connection).inc()
                log.warning("gateway inspection failed for %s: %s", connection, exc.code)
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
                "error_code": error_code,
                "diagnostic": None if diagnostic is None else {
                    "configured": diagnostic.configured,
                    "ike_established": diagnostic.ike_established,
                    "ike_negotiating": diagnostic.ike_negotiating,
                    "child_installed": diagnostic.child_installed,
                    "child_negotiating": diagnostic.child_negotiating,
                },
            }, sort_keys=True),
        )
        result: dict[str, Any] = {
            "alertname": name, "connection": connection_label, "decision": decision,
        }
        if error_code:
            result["error_code"] = error_code
        if connection and alert.status == "firing" and payload.status == "firing" and diagnostic is not None:
            result["diagnostic"] = {
                "state": diagnostic.state,
                "configured": diagnostic.configured,
                "ike_established": diagnostic.ike_established,
                "ike_negotiating": diagnostic.ike_negotiating,
                "child_installed": diagnostic.child_installed,
                "child_negotiating": diagnostic.child_negotiating,
            }
        decisions.append(result)
    return decisions


def create_app(config: Config, inspector: Inspector | None = None) -> FastAPI:
    app = FastAPI(title="IPsec Recovery Controller", version="0.3.0", docs_url=None, redoc_url=None)

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
        decisions = await run_in_threadpool(evaluate, config, payload, inspector)
        WEBHOOKS.labels(outcome="accepted").inc()
        return {"mode": config.mode, "decisions": decisions, "recovery_executed": False}

    return app
