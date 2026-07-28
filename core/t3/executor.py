"""Deterministic, non-executing boundary for approved T3 control-flow tests."""

from __future__ import annotations

from dataclasses import dataclass

from core.t3.models import T3ActionRequest, T3Stage


@dataclass(frozen=True)
class MockT3ExecutionPlan:
    """Validated identifiers only; credential and evidence references are excluded."""

    action_id: str
    stage: T3Stage
    source_asset_id: str
    destination_asset_id: str | None
    capability_id: str
    command_scope: tuple[str, ...]

    @classmethod
    def from_request(cls, request: T3ActionRequest) -> MockT3ExecutionPlan:
        return cls(
            action_id=request.action_id,
            stage=request.stage,
            source_asset_id=request.source_asset_id,
            destination_asset_id=request.destination_asset_id,
            capability_id=request.capability_id,
            command_scope=tuple(request.command_scope),
        )


@dataclass(frozen=True)
class MockT3Outcome:
    status: str
    mock_only: bool
    real_action_performed: bool
    action_id: str
    stage: str
    capability_id: str


class MockT3Executor:
    """Records invocation and returns a fixed result without performing any action."""

    def __init__(self) -> None:
        self.invocation_count = 0

    def run(self, plan: MockT3ExecutionPlan) -> MockT3Outcome:
        self.invocation_count += 1
        return MockT3Outcome(
            status="mock_completed",
            mock_only=True,
            real_action_performed=False,
            action_id=plan.action_id,
            stage=plan.stage.value,
            capability_id=plan.capability_id,
        )
