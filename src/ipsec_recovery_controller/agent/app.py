from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from starlette.concurrency import run_in_threadpool

from ipsec_recovery_controller.adapters.legacy_ipsec import LegacyIPsecAdapter
from ipsec_recovery_controller.agent.config import AgentConfig
from ipsec_recovery_controller.config import Gateway
from ipsec_recovery_controller.diagnostics.inspection import evaluate_snapshot
from ipsec_recovery_controller.diagnostics.models import GatewaySnapshot
from ipsec_recovery_controller.gateway.helper import HelperTransport
from ipsec_recovery_controller.gateway.local import LocalTransport
from ipsec_recovery_controller.gateway.ssh import InspectionError


def certificate_identity(der: bytes) -> set[str]:
    certificate = x509.load_der_x509_certificate(der)
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        identities = set(names.get_values_for_type(x509.DNSName))
        identities.update(str(value) for value in names.get_values_for_type(x509.UniformResourceIdentifier))
        return identities
    except x509.ExtensionNotFound:
        return {item.value for item in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)}


def filter_snapshot(snapshot: GatewaySnapshot, mappings) -> GatewaySnapshot:
    """Expose only configured names/selectors and their authorized IKE parents."""
    mappings = tuple(mappings)
    ikes = tuple(sa for sa in snapshot.ike_sas
                 if any(sa.name == mapping.ike_connection for mapping in mappings))
    for sa in snapshot.child_sas:
        for mapping in mappings:
            if sa.name != mapping.child_connection:
                continue
            if any(getattr(mapping, field) is not None and getattr(sa, field) is None
                   for field in ("local_selector", "remote_selector")):
                raise InspectionError("association_ambiguous")
            if (all(getattr(mapping, field) is None or getattr(mapping, field) == getattr(sa, field)
                    for field in ("local_selector", "remote_selector")) and
                    not any(parent.identifier == sa.parent_ike_id and
                            parent.name == mapping.ike_connection for parent in ikes)):
                raise InspectionError("association_ambiguous")
    children = tuple(sa for sa in snapshot.child_sas if any(
        sa.name == mapping.child_connection
        and (mapping.local_selector is None or sa.local_selector == mapping.local_selector)
        and (mapping.remote_selector is None or sa.remote_selector == mapping.remote_selector)
        and any(parent.identifier == sa.parent_ike_id and parent.name == mapping.ike_connection
                for parent in ikes)
        for mapping in mappings))
    names = {mapping.ike_connection for mapping in mappings}
    return GatewaySnapshot(snapshot.configured_connections & names, ikes, children,
                           snapshot.source, snapshot.connections_known)


def create_app(config: AgentConfig, transport: LocalTransport | HelperTransport | None = None) -> FastAPI:
    config.validate_mappings()
    transport = transport or (
        HelperTransport(config.helper_socket, config.helper_timeout_seconds)
        if config.inspection_backend == "helper" else
        LocalTransport(config.ipsec_binary, config.command_timeout_seconds)
    )
    app = FastAPI(title="IPsec Recovery Agent", version="0.3.0", docs_url=None, redoc_url=None)

    def authorize(request: Request) -> None:
        der = request.scope.get("client_cert_der")
        if not isinstance(der, bytes):
            raise HTTPException(401, detail="client certificate required")
        try:
            if config.allowed_client_identity not in certificate_identity(der):
                raise HTTPException(403, detail="client identity not authorized")
        except ValueError:
            raise HTTPException(401, detail="invalid client certificate") from None

    def inspect():
        return LegacyIPsecAdapter(transport).inspect(Gateway(host="localhost"))

    @app.get("/v1/healthz")
    async def healthz(request: Request):
        authorize(request)
        return {"status": "ok", "api_version": "v1"}

    @app.get("/v1/associations")
    async def associations(request: Request):
        authorize(request)
        try:
            snapshot = await run_in_threadpool(inspect)
            snapshot = filter_snapshot(snapshot, config.connections.values())
        except InspectionError as exc:
            raise HTTPException(503, detail={"code": exc.code}) from None
        return jsonable_encoder({"api_version": "v1", "snapshot": snapshot})

    @app.get("/v1/connections/{connection_id}")
    async def connection(request: Request, connection_id: str):
        authorize(request)
        expected = config.connections.get(connection_id)
        if expected is None:
            raise HTTPException(404, detail={"code": "connection_unmapped"})
        try:
            snapshot = await run_in_threadpool(inspect)
            snapshot = filter_snapshot(snapshot, [expected])
        except InspectionError as exc:
            raise HTTPException(503, detail={"code": exc.code}) from None
        diagnostic = evaluate_snapshot(expected.expected(), snapshot)
        return jsonable_encoder({"api_version": "v1", "snapshot": snapshot,
                                 "mapping": expected.model_dump(), "diagnostic": diagnostic})

    return app
