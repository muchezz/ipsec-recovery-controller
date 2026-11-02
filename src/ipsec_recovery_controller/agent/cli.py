"""Run the gateway agent with mandatory mutual TLS."""

from __future__ import annotations

import logging
import os
import ssl

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from ipsec_recovery_controller.agent.app import create_app
from ipsec_recovery_controller.agent.config import load_agent_config


class CertificateH11Protocol(H11Protocol):
    """Add the TLS-verified peer certificate to the ASGI scope, never an HTTP header."""

    def connection_made(self, transport) -> None:
        super().connection_made(transport)
        application = self.app
        ssl_object = transport.get_extra_info("ssl_object")
        # Never accept a certificate from a listener that did not require verification.
        der = (ssl_object.getpeercert(binary_form=True)
               if ssl_object is not None and
               ssl_object.context.verify_mode == ssl.CERT_REQUIRED else None)

        async def verified_application(scope, receive, send):
            scope.pop("client_cert_der", None)
            if der:
                scope["client_cert_der"] = der
            await application(scope, receive, send)

        self.app = verified_application


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = load_agent_config(os.environ.get("IPSEC_AGENT_CONFIG", "/etc/ipsec-recovery-agent/config.yaml"))
    uvicorn.run(
        create_app(config), host=config.server.host, port=config.server.port, workers=1,
        http=CertificateH11Protocol, ssl_certfile=config.server_cert,
        ssl_keyfile=config.server_key, ssl_ca_certs=config.client_ca,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )


if __name__ == "__main__":
    main()
