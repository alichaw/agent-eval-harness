from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from core.investigation.models import Evidence, Finding, InvestigationState, ServiceObservation


def evidence(evidence_id="evidence-1"):
    return Evidence(
        evidence_id=evidence_id,
        asset_id="asset-1",
        capability_id="network.service.inventory",
        tool_name="nmap",
        execution_status="completed",
        facts={},
        raw_output_sha256="a" * 64,
        observed_at=datetime.now(timezone.utc),
        complete=True,
    )


def test_state_accumulates_and_serializes():
    item = evidence()
    state = InvestigationState(
        investigation_id="inv-1",
        asset_id="asset-1",
        objective="Assess risks",
        evidence=[item],
        services=[
            ServiceObservation(
                asset_id="asset-1",
                port=445,
                state="open",
                service="microsoft-ds",
                evidence_id=item.evidence_id,
            )
        ],
        findings=[
            Finding(
                finding_id="finding-1",
                asset_id="asset-1",
                title="SMB exposed",
                classification="observation",
                status="confirmed",
                severity="info",
                confidence=0.99,
                evidence_ids=[item.evidence_id],
            )
        ],
    )
    assert state.model_dump(mode="json")["services"][0]["port"] == 445


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_confidence_is_bounded(confidence):
    with pytest.raises(ValidationError):
        Finding(
            finding_id="f",
            asset_id="asset-1",
            title="bad",
            classification="observation",
            status="confirmed",
            severity="info",
            confidence=confidence,
            evidence_ids=["e"],
        )


def test_finding_requires_evidence():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="f",
            asset_id="asset-1",
            title="bad",
            classification="potential_risk",
            status="unconfirmed",
            severity="low",
            confidence=0.5,
            evidence_ids=[],
        )


def test_state_rejects_dangling_reference():
    with pytest.raises(ValidationError, match="must reference evidence"):
        InvestigationState(
            investigation_id="inv-1",
            asset_id="asset-1",
            objective="Assess",
            evidence=[evidence()],
            services=[
                ServiceObservation(asset_id="asset-1", port=80, state="open", evidence_id="missing")
            ],
        )
