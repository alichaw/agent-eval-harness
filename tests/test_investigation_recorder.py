from core.investigation.models import InvestigationState
from core.investigation.recorder import record_step_result
from core.investigation.router import SERVICE_INVENTORY


def _state():
    return InvestigationState(
        investigation_id="inv-1", asset_id="asset-1", objective="Assess risks"
    )


def test_verified_inventory_adds_evidence_services_and_execution():
    output = "80/tcp open http Apache httpd 2.4.52\nNmap done: 1 host up\n"
    state = record_step_result(
        _state(),
        capability_id=SERVICE_INVENTORY,
        profile_id="inventory",
        tool_name="nmap",
        admitted=True,
        verified=True,
        output=output,
    )
    assert SERVICE_INVENTORY in state.executed_capabilities
    assert state.services[0].port == 80
    assert state.evidence[0].evidence_id == "inv-1-1"


def test_failed_execution_is_not_recorded_as_executed():
    state = record_step_result(
        _state(),
        capability_id="web.http.metadata",
        profile_id="http",
        tool_name="httpx",
        admitted=True,
        verified=False,
        output="error",
    )
    assert "web.http.metadata" in state.failed_capabilities
    assert "web.http.metadata" not in state.executed_capabilities


def test_approval_requirement_is_pending_not_blocked():
    state = record_step_result(
        _state(),
        capability_id=SERVICE_INVENTORY,
        profile_id="inventory",
        tool_name="nmap",
        admitted=False,
        verified=False,
        output="",
        verdict="require_approval",
    )
    assert SERVICE_INVENTORY in state.pending_approval_capabilities
    assert SERVICE_INVENTORY not in state.blocked_capabilities
