from pathlib import Path

import pytest

from ipsec_recovery_controller.adapters.legacy_ipsec import parse_status
from ipsec_recovery_controller.agent.app import filter_snapshot
from ipsec_recovery_controller.agent.config import AgentConnection
from ipsec_recovery_controller.diagnostics.inspection import evaluate_snapshot
from ipsec_recovery_controller.gateway.ssh import InspectionError

FIXTURE = Path(__file__).parent / "fixtures/strongswan-5.8.2-statusall.txt"


def test_full_582_snapshot_and_selectors():
    snapshot = parse_status(FIXTURE.read_text())
    assert len(snapshot.ike_sas) == 62
    assert sum(sa.state == "ESTABLISHED" for sa in snapshot.ike_sas) == 51
    assert sum(sa.state == "CONNECTING" for sa in snapshot.ike_sas) == 11
    mapping = AgentConnection(ike_connection="synthetic-ike-1", child_connection="synthetic-child-1")
    filtered = filter_snapshot(snapshot, [mapping])
    assert [sa.parent_ike_id for sa in filtered.child_sas] == ["1", "1"]
    assert [sa.identifier for sa in filtered.child_sas] == ["10", "11"]
    assert all(sa.spi == "01020304_i 05060708_o" for sa in filtered.child_sas)
    child = filtered.child_sas[0]
    assert (child.bytes_in, child.bytes_out, child.packets_in, child.packets_out) == (1234, 5678, 12, 34)
    assert child.local_selector == "10.1.80.1/32"
    selected = mapping.model_copy(update={"remote_selector": "10.1.66.0/24"})
    result = evaluate_snapshot(selected.expected(), filter_snapshot(snapshot, [selected]))
    assert result.state == "installed_unverified"
    assert result.child_installed == 1
    pending = AgentConnection(ike_connection="synthetic-ike-52", child_connection="synthetic-child-52")
    assert evaluate_snapshot(pending.expected(), filter_snapshot(snapshot, [pending])).state == "ike_negotiating"


@pytest.mark.parametrize("change", ["truncated", "incomplete", "duplicate", "bracket", "selectors", "counts"])
def test_incomplete_582_never_implies_missing(change):
    output = FIXTURE.read_text()
    if change == "truncated":
        output = output[:output.index("synthetic-ike-30[30]:")]
    elif change == "incomplete":
        output = output.replace("INSTALLED, TUNNEL, reqid 1, ESP SPIs: 01020304_i 05060708_o", "", 1)
    elif change == "duplicate":
        output += "synthetic-ike-1[1]: ESTABLISHED\n"
    elif change == "bracket":
        output = output.replace("synthetic-ike-1[1]:", "synthetic-ike-1[1}:", 1)
    elif change == "selectors":
        output = output.replace("10.1.80.1/32 === 10.1.66.0/24", "10.1.80.1/32 === ", 1)
    else:
        output = output.replace("51 up, 11 connecting", "51 up, 12 connecting")
    with pytest.raises(InspectionError) as failure:
        parse_status(output)
    assert failure.value.code == "malformed_output"
