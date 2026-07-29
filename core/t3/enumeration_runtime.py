"""Offline composition and operator-owned T3-B runtime construction."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from core.policy import Policy, T3PolicyRequest, Verdict
from core.profiles import AssetRegistry, ProfileCatalog
from core.safety import ApprovalAuthority, KillSwitch, profile_fingerprint
from core.t3.enumeration import (
    T3B_PLATFORM,
    T3B_PROFILE,
    T3B_SCOPE,
    WINDOWS_ACTION_REGISTRY,
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


def compose_t3b_runtime(
    *,
    proposal: T3BProposal,
    runtime_config_path: str | Path,
    assets_path: str | Path,
    profiles_path: str | Path,
    policy_path: str | Path,
    prerequisite_run_dir: str | Path,
) -> T3BComposition:
    """Validate readiness without resolving a credential or opening a transport."""
    proposal_time = datetime.now(timezone.utc)
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
    prerequisite = load_t3a_prerequisite(prerequisite_run_dir)
    evidence_time = datetime.fromisoformat(prerequisite.observed_at)
    if evidence_time > proposal_time:
        raise ValueError("T3-A prerequisite was produced after the T3-B proposal")
    bindings = build_bindings(
        proposal,
        asset=asset,
        profile_fingerprint=profile_fingerprint(profile),
        runtime_binding_fingerprint=prerequisite.runtime_binding_fingerprint,
        credential_ref=config.credential_ref,
        prerequisite=prerequisite,
    )
    plan = T3BExecutionPlan(
        proposal.asset_id,
        asset["target"],
        22,
        config.pinned_host_key,
        config.credential_ref,
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
) -> Path:
    """The transport is explicit so tests remain fake-backed."""
    selected_resolver = resolver or OperatorFileLabSshCredentialResolver(composition.config)
    executor = T3BExecutor(selected_resolver, transport, kill_switch=kill_switch)
    return run_t3b(
        plan=composition.plan,
        prerequisite=composition.prerequisite,
        executor=executor,
        authority=authority,
        approval_token=token,
        runs_root=runs_root,
    )
