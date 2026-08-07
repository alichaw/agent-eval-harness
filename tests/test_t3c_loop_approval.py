import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.orchestration.catalog import Capability
from core.orchestration.models import ExecutionResult, RunContext, RunStatus
from core.orchestration.t3c_approval import T3CApprovalStore
from core.orchestration.t3c_loop import T3CLoopApproval
from core.profiles import AssetRegistry, ProfileError
from core.t3.impact import ACTION_ID, T3CAgentProposal

TARGET_DIGEST = "c5dea4df7da5375c3612b9e7fd22367333c09c29d1aef58bf3079c508010bac8"


class Executor:
    def __init__(self):
        self.calls = 0

    def execute(self, capability, run):
        self.calls += 1
        return ExecutionResult(
            status="succeeded",
            facts=[{"type": "controlled_impact_verified", "values": {}}],
            evidence_ids=[f"evidence:{run.run_id}:t3c"],
            evidence_types={"successful_sealed_t3c_evidence"},
        )


def capability():
    return Capability(
        capability_id="host.controlled_impact",
        route="t3_controller",
        canonical_action=ACTION_ID,
        phase="t3c",
        risk_tier="high",
        approval_required=True,
        prerequisites=("successful_sealed_t3a_evidence", "successful_sealed_t3b_evidence"),
    )


def context():
    return RunContext(
        run_id="same-agent-run",
        principal="operator",
        asset_id="asset:winsrv2025-01",
        task="controlled impact",
    )


def requested(tmp_path, *, authorization_id="authorization:trusted"):
    store = T3CApprovalStore(tmp_path / "approval.sqlite3")
    loop = T3CLoopApproval(store, kill_switch=lambda: False)
    run = context()
    pending = loop.request(
        run,
        capability(),
        authorization_id=authorization_id,
        protected_scope_digest="a" * 64,
        prerequisite_evidence_references=("evidence:t3a", "evidence:t3b"),
        policy_decision_reference="policy:decision:1",
        deployment_config_version="config:v1",
        now=100,
    )
    return loop, run, pending


def test_protected_local_asset_mapping_and_agent_schema_are_asset_id_only():
    assets = AssetRegistry.from_yaml("config/local/assets.yaml")
    target = assets.resolve("asset:winsrv2025-01")["target"]
    assert hashlib.sha256(target.encode()).hexdigest() == TARGET_DIGEST
    with pytest.raises(ProfileError):
        assets.resolve("asset:unknown")
    with pytest.raises(ValueError):
        T3CAgentProposal.model_validate({"action_id": ACTION_ID, "target": target})
    mutable_view = assets.resolve("asset:winsrv2025-01")
    mutable_view["target"] = "observation-controlled"
    assert (
        hashlib.sha256(assets.resolve("asset:winsrv2025-01")["target"].encode()).hexdigest()
        == TARGET_DIGEST
    )


def test_t3c_missing_authorization_denies_before_pending_or_dispatch(tmp_path):
    store = T3CApprovalStore(tmp_path / "approval.sqlite3")
    loop = T3CLoopApproval(store, kill_switch=lambda: False)
    run = context()
    with pytest.raises(ValueError, match="authorization_required"):
        loop.request(
            run,
            capability(),
            authorization_id="",
            protected_scope_digest="a" * 64,
            prerequisite_evidence_references=("evidence:t3a", "evidence:t3b"),
            policy_decision_reference="policy:1",
            deployment_config_version="config:v1",
        )
    assert run.tool_calls == 0 and run.pending_action_id is None


def test_approve_does_not_dispatch_and_resume_observes_then_continues(tmp_path):
    loop, run, pending = requested(tmp_path)
    executor = Executor()
    assert run.status is RunStatus.WAITING_FOR_APPROVAL and run.tool_calls == 0
    permit = loop.approve(run, approved_by="reviewer", now=110)
    assert run.status is RunStatus.APPROVED_PENDING_RESUME
    assert executor.calls == 0 and run.tool_calls == 0
    resumed = loop.resume(
        run,
        capability(),
        permit,
        executor,
        protected_scope_digest=pending.protected_scope_digest,
        prerequisite_evidence_references=pending.prerequisite_evidence_references,
        deployment_config_version=pending.deployment_config_version,
        now=111,
    )
    assert resumed.run_id == "same-agent-run"
    assert resumed.status is RunStatus.RUNNING
    assert resumed.tool_calls == executor.calls == 1
    assert resumed.observations[-1].capability_id == "host.controlled_impact"
    assert resumed.observations[-1].evidence_ids


def test_permit_binding_expiry_replay_and_cancel_fail_closed(tmp_path):
    loop, run, pending = requested(tmp_path)
    permit = loop.approve(run, approved_by="reviewer", ttl_seconds=5, now=110)
    executor = Executor()
    with pytest.raises(ValueError, match="pending_action_binding_mismatch"):
        loop.resume(
            run,
            capability(),
            permit,
            executor,
            protected_scope_digest="b" * 64,
            prerequisite_evidence_references=pending.prerequisite_evidence_references,
            deployment_config_version="config:v1",
            now=111,
        )
    assert executor.calls == run.tool_calls == 0
    with pytest.raises(ValueError, match="expired"):
        loop.store.consume(permit, pending, now=116)
    assert executor.calls == 0


def test_two_concurrent_resume_claims_consume_permit_at_most_once(tmp_path):
    loop, run, pending = requested(tmp_path)
    permit = loop.approve(run, approved_by="reviewer", now=110)

    def consume():
        try:
            loop.store.consume(permit, pending, now=111)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(), range(2)))
    assert results.count(True) == 1


def test_two_concurrent_loop_resumes_dispatch_at_most_once(tmp_path):
    loop, run, pending = requested(tmp_path)
    permit = loop.approve(run, approved_by="reviewer", now=110)
    executor = Executor()

    def resume():
        local = run.model_copy(deep=True)
        try:
            loop.resume(
                local,
                capability(),
                permit,
                executor,
                protected_scope_digest=pending.protected_scope_digest,
                prerequisite_evidence_references=pending.prerequisite_evidence_references,
                deployment_config_version=pending.deployment_config_version,
                now=111,
            )
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: resume(), range(2)))
    assert results.count(True) == 1
    assert executor.calls == 1


def test_denied_pending_action_cannot_be_approved_or_resumed(tmp_path):
    loop, run, _ = requested(tmp_path)
    loop.deny(run)
    assert run.status is RunStatus.APPROVAL_DENIED and run.tool_calls == 0
    with pytest.raises(ValueError, match="not_waiting"):
        loop.approve(run, approved_by="reviewer", now=110)


def test_second_t3c_action_cannot_reuse_first_permit(tmp_path):
    loop, run, pending = requested(tmp_path)
    permit = loop.approve(run, approved_by="reviewer", now=110)
    loop.store.consume(permit, pending, now=111)
    second = pending.__class__(
        **{
            **pending.__dict__,
            "pending_action_id": "pending:second",
            "protected_scope_digest": "b" * 64,
        }
    )
    with pytest.raises(ValueError, match="binding_mismatch"):
        loop.store.consume(permit, second, now=112)
