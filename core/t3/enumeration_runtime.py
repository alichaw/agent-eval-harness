"""Offline composition and operator-owned T3-B runtime construction."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.artifacts import ArtifactSealAuthority
from core.policy import Policy, T3PolicyRequest, Verdict
from core.profiles import AssetRegistry, ProfileCatalog
from core.safety import ApprovalAuthority, KillSwitch, profile_fingerprint
from core.t3.access import SESSION_POLICY, T3CommandId
from core.t3.binding import RuntimeBinding, canonical_digest, host_key_identity
from core.t3.enumeration import (
    T3B_PLATFORM,
    T3B_PROFILE,
    T3B_SCOPE,
    WINDOWS_ACTION_REGISTRY,
    ExecutionMode,
    T3APrerequisite,
    T3BBindings,
    T3BExecutionPlan,
    T3BExecutor,
    T3BProposal,
    T3BTransport,
    build_bindings,
    load_t3a_prerequisite,
    run_t3b,
)
from core.t3.executor import LabSshCredentialResolver, valid_pinned_host_key
from core.t3.runtime import (
    OperatorFileLabSshCredentialResolver,
    T3RuntimeConfig,
    _read_private_config,
)


@dataclass(frozen=True)
class T3BComposition:
    proposal: T3BProposal
    prerequisite: T3APrerequisite
    bindings: T3BBindings
    plan: T3BExecutionPlan
    assets: AssetRegistry
    config: T3RuntimeConfig


def validate_prerequisite_freshness(
    observed_at: str,
    *,
    proposal_time: datetime,
    max_age_seconds: int,
    clock_skew_seconds: int,
) -> datetime:
    """Validate policy-controlled prerequisite age with inclusive boundaries."""

    if proposal_time.tzinfo is None or proposal_time.utcoffset() is None:
        raise ValueError("timezone-aware proposal time required")
    try:
        evidence_time = datetime.fromisoformat(observed_at)
    except ValueError as exc:
        raise ValueError("T3-A prerequisite timestamp invalid") from exc
    if evidence_time.tzinfo is None or evidence_time.utcoffset() is None:
        raise ValueError("T3-A prerequisite timestamp must be timezone-aware")
    if (
        type(max_age_seconds) is not int
        or max_age_seconds <= 0
        or type(clock_skew_seconds) is not int
        or clock_skew_seconds < 0
    ):
        raise ValueError("T3-A freshness policy invalid")
    if evidence_time > proposal_time + timedelta(seconds=clock_skew_seconds):
        raise ValueError("T3-A prerequisite was produced after the T3-B proposal")
    if proposal_time - evidence_time > timedelta(seconds=max_age_seconds):
        raise ValueError("T3-A prerequisite is stale")
    return evidence_time


def compose_t3b_runtime(
    *,
    proposal: T3BProposal,
    runtime_config_path: str | Path,
    assets_path: str | Path,
    profiles_path: str | Path,
    policy_path: str | Path,
    prerequisite_run_dir: str | Path,
    artifact_authority: ArtifactSealAuthority,
    execution_mode: ExecutionMode = ExecutionMode.LAB_REAL,
    now: datetime | None = None,
) -> T3BComposition:
    """Validate readiness without resolving a credential or opening a transport."""
    proposal_time = now or datetime.now(timezone.utc)
    if proposal_time.tzinfo is None or proposal_time.utcoffset() is None:
        raise ValueError("timezone-aware proposal time required")
    config = _read_private_config(runtime_config_path)
    if config.asset_id != proposal.asset_id or config.profile_id != proposal.profile_id:
        raise ValueError("operator configuration does not match T3-B proposal")
    if not valid_pinned_host_key(config.pinned_host_key):
        raise ValueError("pinned host key required")
    assets = AssetRegistry.from_yaml(assets_path)
    asset = dict(assets.resolve(proposal.asset_id))
    asset.update(
        credential_ref=config.credential_ref,
        ssh_host_key=config.pinned_host_key,
    )
    if (
        asset.get("asset_type") != "host"
        or asset.get("platform") != T3B_PLATFORM
        or asset.get("execution_scope") != T3B_SCOPE
        or asset.get("ssh_port") != 22
    ):
        raise ValueError("registered Windows lab asset required")
    profile = ProfileCatalog.from_yaml(profiles_path).get(proposal.profile_id)
    if (
        profile.profile_id != T3B_PROFILE
        or profile.tool_id != "t3-windows-enumeration-readonly"
        or not profile.approval_required
    ):
        raise ValueError("T3-B profile is not safely configured")
    policy = Policy.from_yaml(policy_path)
    policy_decision = policy.check_t3(
        T3PolicyRequest(
            capability_id=T3B_PROFILE,
            stage="windows_enumeration",
            target=asset["target"],
        )
    )
    if policy_decision.verdict is not Verdict.REQUIRE_APPROVAL:
        raise ValueError("T3-B policy authorization denied")
    prerequisite = load_t3a_prerequisite(
        prerequisite_run_dir,
        seal_authority=artifact_authority,
    )
    max_age = policy.t3_prerequisite_max_age_seconds
    skew = policy.t3_prerequisite_clock_skew_seconds
    validate_prerequisite_freshness(
        prerequisite.observed_at,
        proposal_time=proposal_time,
        max_age_seconds=max_age,
        clock_skew_seconds=skew,
    )

    prerequisite_profile = ProfileCatalog.from_yaml(profiles_path).get(prerequisite.profile_id)
    prerequisite_config = config.model_copy(update={"profile_id": prerequisite.profile_id})
    algorithm, host_key_fingerprint = host_key_identity(config.pinned_host_key)
    current_runtime = RuntimeBinding(
        asset_id=proposal.asset_id,
        target_identity=canonical_digest(
            {"asset_id": proposal.asset_id, "target": asset["target"]}
        ),
        host=asset["target"],
        port=asset["ssh_port"],
        credential_ref=config.credential_ref,
        principal=config.username,
        host_key_algorithm=algorithm,
        host_key_fingerprint=host_key_fingerprint,
        transport_type="ssh_paramiko",
        runtime_config_digest=canonical_digest(prerequisite_config.model_dump(mode="json")),
        asset_registry_digest=canonical_digest(asset),
        policy_digest=canonical_digest(asdict(policy)),
        profile_digest=profile_fingerprint(prerequisite_profile),
        prerequisite_stage=prerequisite.stage,
        prerequisite_capability=prerequisite.profile_id,
        session_limits_digest=canonical_digest(asdict(SESSION_POLICY)),
        action_registry_digest=canonical_digest([item.value for item in T3CommandId]),
    )
    bindings = build_bindings(
        proposal,
        asset=asset,
        profile_fingerprint=profile_fingerprint(profile),
        runtime_binding_fingerprint=current_runtime.fingerprint,
        credential_ref=config.credential_ref,
        prerequisite=prerequisite,
        policy_digest=canonical_digest(asdict(policy)),
        asset_registry_digest=canonical_digest(asset),
        execution_mode=execution_mode,
    )
    plan = T3BExecutionPlan(
        proposal.asset_id,
        asset["target"],
        22,
        config.pinned_host_key,
        config.credential_ref,
        prerequisite.run_id,
        current_runtime,
        bindings,
        tuple(WINDOWS_ACTION_REGISTRY[item] for item in proposal.command_ids),
    )
    return T3BComposition(
        proposal,
        prerequisite,
        bindings,
        plan,
        assets.with_asset_overrides(proposal.asset_id, asset),
        config,
    )


def execute_t3b_composition(
    composition: T3BComposition,
    *,
    authority: ApprovalAuthority,
    token: str,
    transport: T3BTransport,
    runs_root: str | Path,
    kill_switch: KillSwitch,
    resolver: LabSshCredentialResolver | None = None,
    enablement: str | None = None,
) -> Path:
    """The transport is explicit so tests remain fake-backed."""
    selected_resolver = resolver or OperatorFileLabSshCredentialResolver(composition.config)
    mode = getattr(transport, "execution_mode", None)
    executor = T3BExecutor(
        selected_resolver,
        transport,
        kill_switch=kill_switch,
        execution_mode=mode,
        enablement=enablement,
        require_invalidation=True,
    )
    return run_t3b(
        plan=composition.plan,
        prerequisite=composition.prerequisite,
        executor=executor,
        authority=authority,
        approval_token=token,
        runs_root=runs_root,
    )
