"""Operator-only composition for bounded T3-A execution."""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from core.investigation.models import InvestigationState
from core.policy import Policy, T3PolicyRequest, Verdict
from core.profiles import AssetRegistry, ProfileCatalog
from core.safety import ApprovalAuthority, KillSwitch
from core.t3.access import (
    T3_ACCESS_PROFILE,
    BoundedLabSshT3Executor,
    ParamikoBoundedSshTransport,
    T3AccessProposal,
    materialize_t3_access_request,
    t3_access_approval_fingerprint,
)
from core.t3.executor import (
    LabSshCredential,
    LabSshCredentialResolver,
    valid_pinned_host_key,
)
from core.t3.gate import validate_t3_prerequisites
from core.t3.models import T3ActionRequest

T3_ENABLEMENT_ENV = "T3_LAB_EXECUTION_ENABLED"


class T3RuntimeConfig(BaseModel):
    """Operator-owned values; this model is never exposed as agent input."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=128)
    profile_id: str = Field(pattern=r"^t3-access-bounded$")
    credential_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
    username: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
    private_key_path: str = Field(min_length=1)
    pinned_host_key: str = Field(min_length=1)


class OperatorFileLabSshCredentialResolver(LabSshCredentialResolver):
    """Load one Ed25519 key only after Controller consumes the matching approval."""

    def __init__(self, config: T3RuntimeConfig):
        self._config = config
        self.invocation_count = 0

    def resolve_for_lab_ssh(self, credential_handle: str, source_asset_id: str) -> LabSshCredential:
        self.invocation_count += 1
        if (
            credential_handle != self._config.credential_ref
            or source_asset_id != self._config.asset_id
        ):
            raise ValueError("credential binding rejected")
        try:
            import paramiko

            private_key = paramiko.Ed25519Key.from_private_key_file(self._config.private_key_path)
        except Exception as exc:  # noqa: BLE001 - path/key details must not escape
            raise ValueError("operator credential unavailable") from exc
        return LabSshCredential(self._config.username, private_key)


@dataclass(frozen=True)
class T3RuntimeComposition:
    request: T3ActionRequest
    assets: AssetRegistry
    policy: Policy
    config: T3RuntimeConfig
    fingerprint: str


def _read_private_config(path: str | Path) -> T3RuntimeConfig:
    config_path = Path(path)
    try:
        mode = stat.S_IMODE(config_path.stat().st_mode)
        raw = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("operator runtime configuration unavailable") from exc
    if mode & 0o077:
        raise ValueError("operator runtime configuration must have mode 0600")
    try:
        return T3RuntimeConfig.model_validate_json(raw)
    except ValueError as exc:
        raise ValueError("operator runtime configuration invalid") from exc


def _action_id(proposal: T3AccessProposal, state: InvestigationState) -> str:
    document = {
        "proposal": proposal.model_dump(mode="json"),
        "investigation_id": state.investigation_id,
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return f"t3a-{hashlib.sha256(canonical).hexdigest()[:24]}"


def compose_t3_runtime(
    *,
    proposal: T3AccessProposal,
    runtime_config_path: str | Path,
    assets_path: str | Path,
    profiles_path: str | Path,
    policy_path: str | Path,
    investigation_state_path: str | Path,
) -> T3RuntimeComposition:
    config = _read_private_config(runtime_config_path)
    if config.asset_id != proposal.asset_id or config.profile_id != proposal.profile_id:
        raise ValueError("operator configuration does not match proposal")
    if not valid_pinned_host_key(config.pinned_host_key):
        raise ValueError("pinned Ed25519 host key required")

    assets = AssetRegistry.from_yaml(assets_path)
    source = dict(assets.resolve(proposal.asset_id))
    if source.get("credential_ref") not in (None, config.credential_ref):
        raise ValueError("registered credential reference mismatch")
    source["credential_ref"] = config.credential_ref
    source["ssh_host_key"] = config.pinned_host_key
    composed_assets = assets.with_asset_overrides(proposal.asset_id, source)

    catalog = ProfileCatalog.from_yaml(profiles_path)
    profile = catalog.get(proposal.profile_id)
    if (
        profile.profile_id != T3_ACCESS_PROFILE
        or profile.tool_id != "t3-controlled-access"
        or not profile.approval_required
    ):
        raise ValueError("T3-A profile is not safely configured")
    policy = Policy.from_yaml(policy_path)
    state = InvestigationState.model_validate_json(
        Path(investigation_state_path).read_text(encoding="utf-8")
    )
    request = materialize_t3_access_request(
        proposal,
        action_id=_action_id(proposal, state),
        state=state,
        assets=composed_assets,
    )

    target = source.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("registered target invalid")
    decision = policy.check_t3(
        T3PolicyRequest(
            capability_id=request.capability_id,
            stage=request.stage.value,
            target=target.strip(),
        )
    )
    if decision.verdict is not Verdict.REQUIRE_APPROVAL:
        raise ValueError("T3-A policy authorization denied")
    gate = validate_t3_prerequisites(request, state, composed_assets)
    if gate.denied:
        raise ValueError("T3-A prerequisite validation denied")
    return T3RuntimeComposition(
        request=request,
        assets=composed_assets,
        policy=policy,
        config=config,
        fingerprint=t3_access_approval_fingerprint(request),
    )


def build_t3_controller_and_executor(
    *,
    composition: T3RuntimeComposition,
    runs_root: str | Path,
    approval_authority: ApprovalAuthority,
    kill_switch_path: str | Path,
    enablement: str | None,
):
    """Construct the only live route; callers cannot substitute an executor."""
    from core.controller import Controller

    resolver = OperatorFileLabSshCredentialResolver(composition.config)
    kill_switch = KillSwitch(Path(kill_switch_path))
    executor = BoundedLabSshT3Executor(
        resolver,
        ParamikoBoundedSshTransport(),
        enablement=enablement,
        permitted_target=composition.assets.resolve(composition.request.source_asset_id)["target"],
        kill_switch=kill_switch,
    )
    controller = Controller(
        runs_root=runs_root,
        policy=composition.policy,
        assets=composition.assets,
        approval_authority=approval_authority,
        kill_switch=kill_switch,
    )
    return controller, executor
