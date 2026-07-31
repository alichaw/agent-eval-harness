"""
core/schemas/models.py

Pydantic models for the agent-eval-harness. Three schema families, all versioned:
  - TaskSpec    : a test case (loaded from cases/vN/*.yaml)
  - TraceEvent  : one line in run_dir/trace.jsonl (append-only event stream)
  - AgentResult : what an AgentAdapter.run() returns

WEEK 2 RULE: freeze v1. After this, ADD fields only — never change the meaning
of an existing field. That is exactly what keeps old traces re-scorable in W5.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "v1"


# ---------------------------------------------------------------------------
# Enums — load-bearing. Getting these right now saves real pain in W5/W6.
# ---------------------------------------------------------------------------


class ToolMode(str, Enum):
    """How a tool call was ACTUALLY executed. Recorded per-event in the trace."""

    REAL = "real"  # really ran — sandbox only
    MOCK = "mock"  # fake result, used to control failures deterministically
    SIMULATED = "simulated"  # fake result, executed=false (destructive-safe)


class CaseToolMode(str, Enum):
    """Declared at the CASE level. A case may allow several modes -> 'mixed'.
    Deliberately NOT the same enum as ToolMode: a single trace event is always
    exactly one of real/mock/simulated, but a case can say 'this scenario mixes
    them'. Keeping them separate kills that ambiguity before it starts."""

    REAL = "real"
    MOCK = "mock"
    SIMULATED = "simulated"
    MIXED = "mixed"


class TraceEventType(str, Enum):
    """The `type` tag on every trace event. Evaluator/verifier dispatch on this."""

    PROMPT = "prompt"
    PLAN = "plan"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    POLICY_EVENT = "policy_event"
    CLAIMED_ACTION = "claimed_action"
    VERIFICATION = "verification"
    ERROR = "error"
    TIMEOUT = "timeout"
    COST = "cost"
    BUDGET = "budget"
    EXECUTION_STATE = "execution_state"


# ---------------------------------------------------------------------------
# AgentResult — the adapter contract's return type (see Part 4.2)
# ---------------------------------------------------------------------------


class ToolCall(BaseModel):
    name: str
    params: dict[str, Any] = Field(default_factory=dict)
    ts: float  # unix epoch seconds


class AgentResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    task_id: str
    completed: bool
    tool_calls: list[ToolCall] = Field(default_factory=list)
    final_output: str = ""
    # What the agent SAYS it did. Never trusted directly — the Action Verifier
    # checks each of these against environment-side evidence (W6).
    claimed_actions: list[str] = Field(default_factory=list)
    raw_trace_path: str


# ---------------------------------------------------------------------------
# TraceEvent — one JSONL line, append-only event stream (see Part 5.3)
# ---------------------------------------------------------------------------


class TraceEvent(BaseModel):
    """One event in trace.jsonl.

    THE 'do I split this?' DECISION you flagged:
    This is ONE flexible event with a `type` discriminator plus a bag of
    optional, type-specific fields. That's the pragmatic W2 choice. The stricter
    alternative is a discriminated union (one model per event type). Start
    flexible; only split if the optional-field soup gets genuinely painful.
    Whatever you pick, keep ts/run_id/seq/type mandatory on EVERY event.
    """

    schema_version: str = SCHEMA_VERSION
    ts: float
    run_id: str
    seq: int
    type: TraceEventType

    # --- optional, depend on `type`. Extend as you add event kinds. ---
    tool: str | None = None
    params: dict[str, Any] | None = None
    executed: bool | None = None
    mode: ToolMode | None = None
    status: int | None = None
    text: str | None = None  # prompt / plan / claimed_action payload
    # verification fields (claimed × verified 2×2 — your moat)
    claim_seq: int | None = None
    verified: bool | None = None
    evidence: str | None = None
    # policy / error / cost
    rule: str | None = None
    verdict: str | None = None
    error_class: str | None = None  # ties to your error taxonomy (Part 5.4)
    cost_usd: float | None = None
    tokens: int | None = None
    state: str | None = None
    command_id: str | None = None
    attempted: bool | None = None
    return_code: int | None = None
    outcome: str | None = None
    execution_status: str | None = None
    sanitized_stdout: str | None = None
    sanitized_stderr: str | None = None
    duration_seconds: float | None = None
    evidence_predicate_passed: bool | None = None
    action_id: str | None = None
    asset_id: str | None = None
    profile_id: str | None = None
    policy_verdict: str | None = None
    result_digest: str | None = None
    approval_fingerprint: str | None = None
    previous_digest: str | None = None
    event_digest: str | None = None
    execution_mode: str | None = None
    action_definition_digest: str | None = None
    runtime_binding_fingerprint: str | None = None
    assurance_profile: str | None = None
    assurance_config_source: str | None = None
    readiness_status: str | None = None


# ---------------------------------------------------------------------------
# TaskSpec — a test case, loaded from cases/vN/*.yaml (see Part 5.3)
# ---------------------------------------------------------------------------


class SeedFile(BaseModel):
    path: str
    content: str


class CaseSetup(BaseModel):
    target_image: str | None = None
    seed_files: list[SeedFile] = Field(default_factory=list)


class ExpectedBehavior(BaseModel):
    # Free-form strings for v1 (e.g. "unauthorized_action",
    # "data_leakage:/etc/shadow"). TODO(W6): consider a structured type once the
    # verifier needs to PARSE these rather than just compare them.
    must_not: list[str] = Field(default_factory=list)
    should: list[dict[str, Any]] = Field(default_factory=list)


class Scoring(BaseModel):
    success_predicate: str
    weights: dict[str, float] = Field(default_factory=dict)


class TaskSpec(BaseModel):
    # extra="forbid": a typo'd key in a case YAML fails loudly instead of being
    # silently ignored. Cheap insurance for case authoring.
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    version: str = SCHEMA_VERSION
    category: str
    description: str = ""
    setup: CaseSetup = Field(default_factory=CaseSetup)
    task: str
    allowed_tools: list[str] = Field(default_factory=list)
    expected_behavior: ExpectedBehavior = Field(default_factory=ExpectedBehavior)
    scoring: Scoring
    tool_mode: CaseToolMode = CaseToolMode.REAL
    target: str = ""
    agent_params: dict[str, Any] = Field(default_factory=dict)
    t3_credential_ref: str = ""
    t3_written_justification: str = ""
    asset_id: str = ""
    profile_id: str = ""
    objective: str = ""
    command_ids: list[str] = Field(default_factory=list)
    t3_scenario: str = ""


if __name__ == "__main__":
    # quick self-check
    models = (TaskSpec, TraceEvent, AgentResult, ToolCall)
    print("schemas import ok:", [m.__name__ for m in models])
