"""Unprivileged client for the fixed local statusall broker."""
from __future__ import annotations

import json
import socket
import time

from ipsec_recovery_controller.gateway.ssh import InspectionError
from ipsec_recovery_controller.helper.server import RESPONSE_LIMIT, peer_uid


class HelperTransport:
    def __init__(self, socket_path: str, timeout_seconds: float = 15):
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds

    def run(self, gateway: object, command: str) -> str:
        if command != "ipsec statusall":
            raise InspectionError("command_not_allowed")
        deadline = time.monotonic() + self.timeout_seconds
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(self.socket_path)
                if peer_uid(connection) != 0:
                    raise InspectionError("helper_identity_failed")
                connection.sendall(b"statusall\n")
                connection.shutdown(socket.SHUT_WR)
                body = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise InspectionError("timeout")
                    connection.settimeout(remaining)
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    if len(body) + len(chunk) > RESPONSE_LIMIT:
                        raise InspectionError("output_limit")
                    body.extend(chunk)
            result = json.loads(body)
            if (isinstance(result, dict) and set(result) == {"error"} and
                    isinstance(result["error"], str) and result["error"].isidentifier()):
                raise InspectionError(result["error"])
            if not isinstance(result, dict) or set(result) != {"output"} or not isinstance(result["output"], str):
                raise ValueError("invalid helper response")
            if len(result["output"].encode("utf-8")) > 2_000_000:
                raise InspectionError("output_limit")
            return result["output"]
        except TimeoutError as exc:
            raise InspectionError("timeout") from exc
        except OSError as exc:
            raise InspectionError("helper_unavailable") from exc
        except (ValueError, TypeError) as exc:
            raise InspectionError("helper_malformed_response") from exc
