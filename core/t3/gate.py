"""Fail-closed prerequisite checks for control-only T3 requests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from core.investigation.models import Evidence, InvestigationState
from core.profiles import AssetRegistry
from core.t3.models import T3ActionRequest, T3Stage

AUTHORIZED_EVIDENCE_MAX_AGE = timedelta(hours=24)


@dataclass(frozen=True)
class T3GateDecision:
    allowed: bool
    rule: str
    detail: str = ""

    @property
    def denied(self) -> bool:
        return not self.allowed


def _deny(rule: str, detail: str = "") -> T3GateDecision:
    return T3GateDecision(False, rule, detail)


def _completed(item: Evidence) -> bool:
    return (
        item.execution_status == "completed"
        and item.complete
        and not item.truncated
        and item.error is None
    )


def _proves_low_privilege_access(item: Evidence) -> bool:
    return item.facts.get("access_level") == "low_privilege"


def _proves_access(item: Evidence) -> bool:
    return item.facts.get("access_confirmed") is True or _proves_low_privilege_access(item)


def proves_ssh_reachability(item: Evidence, state: InvestigationState) -> bool:
    """Require structured TCP/22 SSH reachability, never an agent narrative."""
    linked_services = [
        service for service in state.services if service.evidence_id == item.evidence_id
    ]
    if any(
        service.port == 22
        and service.protocol.lower() == "tcp"
        and service.state.lower() in {"open", "reachable"}
        and (service.service or "").lower() in {"ssh", "openssh"}
        for service in linked_services
    ):
        return True
    facts = item.facts
    ports = facts.get("open_ports")
    port_22 = facts.get("port") == 22 or (
        isinstance(ports, list) and any(value == 22 for value in ports)
    )
    return (
        port_22
        and str(facts.get("protocol", "tcp")).lower() == "tcp"
        and str(facts.get("service", "")).lower() in {"ssh", "openssh"}
        and str(facts.get("state", facts.get("status", ""))).lower()
        in {"open", "reachable", "available"}
    )


def authorized_ssh_evidence_valid(
    item: Evidence,
    state: InvestigationState,
    *,
    now: datetime | None = None,
) -> bool:
    reference_time = now or datetime.now(timezone.utc)
    observed_at = item.observed_at
    if observed_at.tzinfo is None:
        return False
    age = reference_time - observed_at
    return (
        _completed(item)
        and timedelta(0) <= age <= AUTHORIZED_EVIDENCE_MAX_AGE
        and proves_ssh_reachability(item, state)
    )


def validate_t3_prerequisites(
    request: T3ActionRequest,
    state: InvestigationState,
    assets: AssetRegistry,
) -> T3GateDecision:
    """Validate investigation and registry prerequisites without executing anything."""

    try:
        if state.asset_id != request.source_asset_id:
            return _deny("wrong_source_asset", "investigation does not belong to source asset")
        assets.resolve(request.source_asset_id)
        if request.destination_asset_id is not None:
            assets.resolve(request.destination_asset_id)

        evidence_by_id = {item.evidence_id: item for item in state.evidence}
        selected: list[Evidence] = []
        for evidence_id in request.evidence_refs:
            item = evidence_by_id.get(evidence_id)
            if item is None:
                return _deny("dangling_evidence")
            if item.asset_id != request.source_asset_id:
                return _deny("wrong_asset_evidence")
            if not _completed(item):
                return _deny("incomplete_evidence")
            selected.append(item)

        if request.stage is T3Stage.INITIAL_ACCESS:
            findings = {item.finding_id: item for item in state.findings}
            if not request.finding_refs:
                return _deny("finding_required")
            for finding_id in request.finding_refs:
                finding = findings.get(finding_id)
                if finding is None:
                    return _deny("dangling_finding")
                if (
                    finding.asset_id != request.source_asset_id
                    or finding.status != "confirmed"
                    or finding.classification not in {"confirmed_vulnerability", "exploitable"}
                ):
                    return _deny("unsuitable_finding")
                if not finding.evidence_ids or not set(finding.evidence_ids) <= set(
                    request.evidence_refs
                ):
                    return _deny("finding_evidence_missing")
        elif request.stage is T3Stage.AUTHORIZED_ACCESS:
            if request.finding_refs:
                return _deny("authorized_access_finding_not_allowed")
            if not selected or not any(
                authorized_ssh_evidence_valid(item, state) for item in selected
            ):
                return _deny("ssh_reachability_not_proven")
        elif request.stage is T3Stage.PRIVILEGE_ESCALATION:
            if not any(_proves_low_privilege_access(item) for item in selected):
                return _deny("low_privilege_access_not_proven")
        elif request.stage is T3Stage.LATERAL_MOVEMENT and not any(
            _proves_access(item) for item in selected
        ):
            return _deny("source_access_not_proven")

        return T3GateDecision(True, "prerequisites_satisfied")
    except Exception:  # noqa: BLE001 - a gate error must always deny
        return _deny(
            "prerequisite_validation_error",
            "prerequisite validation failed",
        )
