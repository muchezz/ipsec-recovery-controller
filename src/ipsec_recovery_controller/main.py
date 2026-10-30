import logging
import os

import uvicorn

from ipsec_recovery_controller.api.app import create_app
from ipsec_recovery_controller.config import load_config


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = load_config(os.environ.get("IPSEC_CONTROLLER_CONFIG", "/etc/ipsec-recovery-controller/config.yaml"))
    uvicorn.run(create_app(config), host=config.server.host, port=config.server.port, workers=1)


if __name__ == "__main__":
    main()
