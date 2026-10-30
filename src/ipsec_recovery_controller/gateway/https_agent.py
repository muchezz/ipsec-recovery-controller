"""mTLS client for versioned, bounded agent snapshots."""

from __future__ import annotations

import ssl

import httpx
from pydantic import ValidationError

from ipsec_recovery_controller.config import Connection, Gateway
from ipsec_recovery_controller.diagnostics.models import GatewaySnapshot
from ipsec_recovery_controller.gateway.agent_response import validate_response
from ipsec_recovery_controller.gateway.ssh import InspectionError


class HTTPSAgentTransport:
    def inspect(self, gateway: Gateway, connection_id: str,
                expected: Connection) -> GatewaySnapshot:
        endpoint = gateway.agent
        assert endpoint is not None
        try:
            context = ssl.create_default_context(cafile=endpoint.ca_file)
            context.load_cert_chain(endpoint.client_cert, endpoint.client_key)
            timeout = httpx.Timeout(endpoint.request_timeout_seconds,
                                    connect=endpoint.connect_timeout_seconds)
            with httpx.Client(verify=context, timeout=timeout, trust_env=False) as client:
                from urllib.parse import quote

                with client.stream("GET", f"{endpoint.url}/v1/connections/{quote(connection_id, safe='')}") as response:
                    if response.status_code == 401 or response.status_code == 403:
                        raise InspectionError("agent_authentication_failed")
                    if response.status_code == 404:
                        raise InspectionError("agent_connection_unmapped")
                    if response.status_code == 503:
                        detail = bytearray()
                        for chunk in response.iter_bytes():
                            if len(detail) + len(chunk) > endpoint.max_response_bytes:
                                raise InspectionError("response_limit")
                            detail.extend(chunk)
                        import json

                        try:
                            code = json.loads(detail)["detail"]["code"]
                        except (ValueError, KeyError, TypeError) as exc:
                            raise InspectionError("agent_malformed_response") from exc
                        if not isinstance(code, str) or not code.isidentifier():
                            raise InspectionError("agent_malformed_response")
                        raise InspectionError(code)
                    if response.status_code != 200:
                        raise InspectionError("agent_http_error")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if len(body) + len(chunk) > endpoint.max_response_bytes:
                            raise InspectionError("response_limit")
                        body.extend(chunk)
            import json

            data = json.loads(body)
            return validate_response(data, expected)
        except InspectionError:
            raise
        except (ssl.SSLError, OSError) as exc:
            raise InspectionError("tls_configuration_failed") from exc
        except httpx.TimeoutException as exc:
            raise InspectionError("timeout") from exc
        except httpx.ConnectError as exc:
            code = "tls_validation_failed" if isinstance(exc.__cause__, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(exc) else "agent_unavailable"
            raise InspectionError(code) from exc
        except httpx.HTTPError as exc:
            raise InspectionError("agent_unavailable") from exc
        except (ValueError, KeyError, TypeError, ValidationError) as exc:
            raise InspectionError("agent_malformed_response") from exc
