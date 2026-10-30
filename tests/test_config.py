import pytest
from ipsec_recovery_controller.config import Config, Connection, AlertRule


def test_unknown_gateway_rejected():
    config = Config(connections={"c": Connection(gateway="missing", ike_connection="i", child_connection="c")})
    with pytest.raises(ValueError, match="unknown gateway"):
        config.validate_mappings()


def test_unknown_connection_rejected():
    config = Config(alerts=[AlertRule(name="a", connection="missing")])
    with pytest.raises(ValueError, match="unknown connection"):
        config.validate_mappings()


def test_recovery_mode_not_accepted():
    with pytest.raises(ValueError):
        Config(mode="recovery")
