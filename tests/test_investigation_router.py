from datetime import datetime, timezone

from core.investigation.models import Evidence, InvestigationState, ServiceObservation
from core.investigation.router import (
    AD_CAPABILITIES,
    SERVICE_INVENTORY,
    SMB_CAPABILITIES,
    WEB_CAPABILITIES,
    get_candidate_capabilities,
)

ALL_CAPABILITIES = {
    SERVICE_INVENTORY,
    *WEB_CAPABILITIES,
    *SMB_CAPABILITIES,
    *AD_CAPABILITIES,
}


def _evidence(status="completed", *, evidence_id="evidence-inventory"):
    return Evidence(
        evidence_id=evidence_id,
        asset_id="asset-1",
        capability_id=SERVICE_INVENTORY,
        tool_name="nmap",
        execution_status=status,
        facts={},
        raw_output_sha256="a" * 64,
        observed_at=datetime.now(timezone.utc),
        complete=status == "completed",
    )


def _state(*services, status="completed", **sets):
    item = _evidence(status)
    observations = [
        ServiceObservation(
            asset_id="asset-1",
            port=port,
            state=state,
            service=service,
            evidence_id=item.evidence_id,
        )
        for port, state, service in services
    ]
    return InvestigationState(
        investigation_id="inv-1",
        asset_id="asset-1",
        objective="Assess risks",
        evidence=[item],
        services=observations,
        **sets,
    )


def test_initial_state_routes_only_inventory():
    state = InvestigationState(
        investigation_id="inv-1", asset_id="asset-1", objective="Assess risks"
    )
    assert get_candidate_capabilities(state, ALL_CAPABILITIES) == [SERVICE_INVENTORY]


def test_http_routes_web_capabilities_in_stable_order():
    state = _state((80, "open", "http"))
    assert get_candidate_capabilities(state, ALL_CAPABILITIES) == list(WEB_CAPABILITIES)


def test_smb_routes_smb_and_ad_capabilities_together():
    # AD posture capabilities (smbmap/rpcclient/netexec) ride the same SMB
    # signal as SMB_CAPABILITIES — they're distinct tools but the same port.
    state = _state((445, "open", "microsoft-ds"))
    expected = [*SMB_CAPABILITIES, *AD_CAPABILITIES]
    assert get_candidate_capabilities(state, ALL_CAPABILITIES) == expected


def test_web_and_smb_are_combined_without_duplicates():
    state = _state((443, "open", "https"), (445, "open", "microsoft-ds"))
    expected = [*WEB_CAPABILITIES, *SMB_CAPABILITIES, *AD_CAPABILITIES]
    assert get_candidate_capabilities(state, ALL_CAPABILITIES) == expected
    assert get_candidate_capabilities(state, ALL_CAPABILITIES) == expected


def test_catalog_filters_unimplemented_capabilities():
    state = _state((80, "open", "http"))
    assert get_candidate_capabilities(state, {WEB_CAPABILITIES[0]}) == [WEB_CAPABILITIES[0]]


def test_executed_failed_and_blocked_capabilities_are_excluded():
    state = _state(
        (80, "open", "http"),
        executed_capabilities={WEB_CAPABILITIES[0]},
        failed_capabilities={WEB_CAPABILITIES[1]},
        blocked_capabilities={WEB_CAPABILITIES[2]},
    )
    assert get_candidate_capabilities(state, ALL_CAPABILITIES) == []


def test_timeout_does_not_retry_or_route_deeper_capabilities():
    state = _state(status="timeout", failed_capabilities={SERVICE_INVENTORY})
    assert get_candidate_capabilities(state, ALL_CAPABILITIES) == []


def test_completed_empty_inventory_is_valid_negative_evidence():
    assert get_candidate_capabilities(_state(), ALL_CAPABILITIES) == []


def test_closed_services_do_not_trigger_follow_up():
    state = _state((80, "closed", "http"), (445, "filtered", "microsoft-ds"))
    assert get_candidate_capabilities(state, ALL_CAPABILITIES) == []


def test_partial_service_rows_do_not_trigger_follow_up():
    state = _state((80, "open", "http"), status="partial")
    assert get_candidate_capabilities(state, ALL_CAPABILITIES) == []
