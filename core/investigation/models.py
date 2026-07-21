"""Domain models for evidence-driven investigations."""
from __future__ import annotations
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field, model_validator

class ServiceObservation(BaseModel):
    asset_id: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    state: str = Field(min_length=1)
    service: str | None = None
    product: str | None = None
    version: str | None = None
    evidence_id: str = Field(min_length=1)

class Evidence(BaseModel):
    evidence_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    capability_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    execution_status: Literal["completed", "partial", "failed", "timeout", "blocked"]
    facts: dict[str, Any] = Field(default_factory=dict)
    raw_output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: datetime
    complete: bool
    truncated: bool = False
    error: str | None = None

class Finding(BaseModel):
    finding_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    classification: Literal["observation", "potential_risk", "confirmed_vulnerability", "exploitable"]
    status: Literal["confirmed", "unconfirmed", "refuted"]
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(min_length=1)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

class InvestigationState(BaseModel):
    investigation_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    services: list[ServiceObservation] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    executed_capabilities: set[str] = Field(default_factory=set)
    blocked_capabilities: set[str] = Field(default_factory=set)
    failed_capabilities: set[str] = Field(default_factory=set)

    @model_validator(mode="after")
    def validate_references(self) -> "InvestigationState":
        ids = {item.evidence_id for item in self.evidence}
        if len(ids) != len(self.evidence):
            raise ValueError("evidence_id values must be unique")
        for service in self.services:
            if service.asset_id != self.asset_id or service.evidence_id not in ids:
                raise ValueError("service must reference evidence for this investigation asset")
        for finding in self.findings:
            refs = set(finding.evidence_ids + finding.contradicting_evidence_ids)
            if finding.asset_id != self.asset_id or not refs <= ids:
                raise ValueError("finding must reference evidence for this investigation asset")
        return self
