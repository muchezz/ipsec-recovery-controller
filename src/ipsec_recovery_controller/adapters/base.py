from __future__ import annotations

from typing import Protocol

from ipsec_recovery_controller.config import Gateway
from ipsec_recovery_controller.diagnostics.models import GatewaySnapshot


class StrongSwanAdapter(Protocol):
    def inspect(self, gateway: Gateway) -> GatewaySnapshot: ...
