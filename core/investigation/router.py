"""Evidence-driven capability routing.

The router proposes implemented capabilities only. Policy remains responsible
for ALLOW, APPROVAL, and DENY decisions.
"""

from __future__ import annotations

from core.investigation.models import InvestigationState

SERVICE_INVENTORY = "network.service.inventory"

WEB_CAPABILITIES = (
    "web.http.metadata",
    "web.content.discovery",
    "web.vulnerability.template_assess",
)
SMB_CAPABILITIES = (
    "windows.smb.posture_assess",
    "windows.smb.anonymous_access_assess",
    "windows.smb.known_vulnerability_assess",
)
# AD posture capabilities routed off the same SMB signal as SMB_CAPABILITIES
# (smbmap/rpcclient/netexec all operate over SMB/RPC, port 139/445) — kept as
# a separate tuple from SMB_CAPABILITIES for readability, not for a different
# trigger. windows.ad.ldap_anonymous_enum and windows.ad.kerberos_asrep_roast_detect
# were removed 2026-07-24: neither has a real backing HexStrike endpoint, so
# routing them would propose a capability the harness can't actually execute.
AD_CAPABILITIES = (
    "windows.ad.smb_share_enum",
    "windows.ad.smb_rid_user_enum",
    "windows.ad.null_session_posture",
)

_HTTP_PORTS = {80, 443, 3000, 8000, 8080, 8443}
_HTTP_SERVICES = {"http", "https", "http-proxy", "http-alt", "ssl/http"}
_SMB_SERVICES = {"microsoft-ds", "netbios-ssn", "smb"}


def get_candidate_capabilities(
    state: InvestigationState,
    available_capabilities: set[str],
) -> list[str]:
    """Return replay-stable next capabilities supported by current evidence."""
    unavailable = (
        state.executed_capabilities | state.failed_capabilities | state.blocked_capabilities
    )

    inventory_evidence = [
        evidence for evidence in state.evidence if evidence.capability_id == SERVICE_INVENTORY
    ]
    if not inventory_evidence:
        return _filter_candidates((SERVICE_INVENTORY,), available_capabilities, unavailable)

    # An incomplete inventory is inconclusive. Retry is intentionally left to
    # retry policy; do not infer an empty/clean target or route deeper scans.
    if not any(evidence.complete for evidence in inventory_evidence):
        return []

    completed_evidence_ids = {
        evidence.evidence_id for evidence in inventory_evidence if evidence.complete
    }
    open_services = [
        service
        for service in state.services
        if service.evidence_id in completed_evidence_ids and service.state.lower() == "open"
    ]

    candidates: list[str] = []
    if any(_is_http(service.port, service.service) for service in open_services):
        candidates.extend(WEB_CAPABILITIES)
    if any(_is_smb(service.port, service.service) for service in open_services):
        candidates.extend(SMB_CAPABILITIES)
        candidates.extend(AD_CAPABILITIES)
    return _filter_candidates(candidates, available_capabilities, unavailable)


def _is_http(port: int, service: str | None) -> bool:
    return port in _HTTP_PORTS or (service or "").lower() in _HTTP_SERVICES


def _is_smb(port: int, service: str | None) -> bool:
    return port in {139, 445} or (service or "").lower() in _SMB_SERVICES


def _filter_candidates(
    candidates: tuple[str, ...] | list[str],
    available: set[str],
    unavailable: set[str],
) -> list[str]:
    return [
        capability
        for capability in dict.fromkeys(candidates)
        if capability in available and capability not in unavailable
    ]
