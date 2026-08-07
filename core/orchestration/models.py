from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RunStatus(str, Enum):
    RUNNING = "running"
    APPROVAL_REQUIRED = "approval_required"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVED_PENDING_RESUME = "approved_pending_resume"
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"
    COMPLETED_WITH_FAILURES = "completed_with_failures"


class PlannerDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability_id: str | None = None
    reason: str = Field(min_length=1, max_length=500)
    stop: bool = False

    @model_validator(mode="after")
    def exactly_one_action(self):
        if self.stop == (self.capability_id is not None):
            raise ValueError("select exactly one capability or stop")
        return self


class Fact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    values: dict[str, Any] = Field(default_factory=dict)


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability_id: str
    status: Literal["succeeded", "failed", "cancelled", "partial"]
    facts: list[Fact] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    asset_id: str
    sanitized: bool = True
    truncated: bool = False
    parser_warnings: list[str] = Field(default_factory=list)


class BudgetLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_steps: int = Field(default=20, ge=1, le=100)
    max_tool_calls: int = Field(default=15, ge=1, le=50)
    max_repeated_capability: int = Field(default=1, ge=1, le=3)
    max_consecutive_failures: int = Field(default=3, ge=1, le=10)
    max_total_duration_seconds: float = Field(default=300, gt=0, le=3600)
    max_output_bytes: int = Field(default=65536, ge=1024, le=1048576)


class RunContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    principal: str
    asset_id: str
    task: str
    status: RunStatus = RunStatus.RUNNING
    observations: list[Observation] = Field(default_factory=list)
    executed: list[str] = Field(default_factory=list)
    planned: list[str] = Field(default_factory=list)
    denied: list[str] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)
    evidence_types: set[str] = Field(default_factory=set)
    pending_capability: str | None = None
    pending_action_id: str | None = None
    steps: int = 0
    tool_calls: int = 0
    consecutive_failures: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stop_reason: str | None = None


class ApprovalGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token_id: str
    principal: str
    run_id: str
    asset_id: str
    capability_id: str
    stage: str
    expires_at: datetime
    credential_id: str = ""
    consumed: bool = False


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["succeeded", "failed", "cancelled", "partial"]
    output: str = ""
    facts: list[Fact] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_types: set[str] = Field(default_factory=set)
    parser_warnings: list[str] = Field(default_factory=list)
    execution_id: str = ""
    failure_stage: str | None = None
    structured_error: dict[str, Any] | None = None
    run_fatal: bool = False
