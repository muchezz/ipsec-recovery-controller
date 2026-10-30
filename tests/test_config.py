import pytest

from ipsec_recovery_controller.config import AgentEndpoint, AlertRule, Config, Connection, Gateway


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


def test_ssh_option_in_host_rejected():
    with pytest.raises(ValueError):
        Gateway(host="-oProxyCommand=evil")


def test_agent_config_requires_https_and_absolute_tls_paths():
    with pytest.raises(ValueError):
        Gateway(transport="agent")
    with pytest.raises(ValueError):
        AgentEndpoint(url="http://example.invalid:8766", ca_file="/tmp/ca", client_cert="/tmp/cert",
                      client_key="/tmp/key")
    with pytest.raises(ValueError):
        AgentEndpoint(url="https://example.invalid:8766", ca_file="relative/ca",
                      client_cert="/tmp/cert", client_key="/tmp/key")


def test_duplicate_gateway_target_rejected():
    config = Config(
        gateways={"g": Gateway(host="192.0.2.1")},
        connections={name: Connection(gateway="g", ike_connection="ike", child_connection="child")
                     for name in ("first", "second")},
    )
    with pytest.raises(ValueError, match="duplicate gateway/connection"):
        config.validate_mappings()
