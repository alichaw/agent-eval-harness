"""core/cli.py — command-line entry point.

    harness run cases/recon_juiceshop.yaml --agent hexstrike
    harness replay runs/<run_id>

Wired to pyproject [project.scripts]:  harness = "core.cli:main"
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from core.controller import Controller
from core.t3.binding import canonical_digest


def _approval_authority(spent_dir: str | Path):
    from core.safety import ApprovalAuthority

    secret = os.environ.get("HARNESS_APPROVAL_SECRET", "")
    if not secret:
        return None
    return ApprovalAuthority(secret.encode(), spent_dir)


def _read_token_file(path: str | None, label: str = "approval token") -> str:
    if not path:
        return ""
    token_path = Path(path)
    try:
        mode = stat.S_IMODE(token_path.stat().st_mode)
        token = token_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise SystemExit(f"{label} file not found: {token_path}") from exc
    if mode & 0o077:
        raise SystemExit(f"{label} file must have mode 0600")
    if not token:
        raise SystemExit(f"{label} file is empty")
    return token


def _make_agent(
    name: str,
    catalog=None,
    assets=None,
    policy=None,
    max_tokens_total: int = 20_000,
    max_cost_usd: float | None = None,
    investigation_state_path: str | None = None,
):
    """Instantiate an adapter by name. Add new agents here — the ONLY place the CLI
    needs to know concrete adapters; everything else uses the base contract."""
    if name == "mock":
        from core.adapters.mock import MockAgent

        return MockAgent()
    if name == "hexstrike":
        from core.adapters.hexstrike import HexStrikeAdapter

        return HexStrikeAdapter()
    if name == "claude":
        from core.adapters.claude import ClaudeAdapter
        from core.adapters.hexstrike import HexStrikeAdapter
        from core.investigation.models import InvestigationState

        if catalog is None or assets is None:
            raise SystemExit("--agent claude requires --profiles and --assets")
        cost_limit = max_cost_usd
        if cost_limit is None and policy is not None:
            cost_limit = policy.max_cost_usd
        state = None
        if investigation_state_path:
            try:
                state = InvestigationState.model_validate_json(
                    Path(investigation_state_path).read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as exc:
                raise SystemExit(f"invalid investigation state: {exc}") from exc
        return ClaudeAdapter(
            catalog,
            assets,
            executor=HexStrikeAdapter(),
            policy=policy,
            max_tokens_total=max_tokens_total,
            max_cost_usd=cost_limit,
            state=state,
        )
    raise SystemExit(f"unknown agent '{name}' (choices: mock, hexstrike, claude)")


def cmd_run(args) -> int:
    catalog = assets = None

    if args.profiles:
        from core.profiles import AssetRegistry, ProfileCatalog

        catalog = ProfileCatalog.from_yaml(args.profiles)
        assets = AssetRegistry.from_yaml(args.assets) if args.assets else None

    policy = None
    if args.policy:
        from core.policy import Policy

        policy = Policy.from_yaml(args.policy)

    agent = _make_agent(
        args.agent,
        catalog=catalog,
        assets=assets,
        policy=policy,
        max_tokens_total=args.max_tokens_total,
        max_cost_usd=args.max_cost_usd,
        investigation_state_path=args.investigation_state,
    )

    from core.safety import KillSwitch

    authority = _approval_authority(args.approval_spent_dir)
    token = _read_token_file(args.approval_token_file)
    job_create_token = _read_token_file(args.job_create_token_file, "job create token")
    if token and authority is None:
        raise SystemExit("HARNESS_APPROVAL_SECRET is required with an approval token")

    controller = Controller(
        runs_root=args.runs_root,
        policy=policy,
        catalog=catalog,
        assets=assets,
        approval_token=token,
        job_create_token=job_create_token,
        approval_authority=authority,
        kill_switch=KillSwitch(Path(args.kill_switch_file)),
    )
    run_dir = controller.run_case(args.case, agent)

    result_path = run_dir / "result.json"
    result = json.loads(result_path.read_text())

    print(f"run dir : {run_dir}")
    print(f"agent   : {args.agent}")

    if result.get("policy_verdict") and result["policy_verdict"] != "allow":
        verdict = result["policy_verdict"].upper()
        rule = result["policy_rule"]
        detail = result["policy_detail"]
        print(f"POLICY  : {verdict} [{rule}] {detail}")

    print(f"completed: {result['completed']}   elapsed: {result['elapsed_s']}s")
    print("artifacts: manifest.json  trace.jsonl  result.json")

    return 0 if result["completed"] else 1


def cmd_approve(args) -> int:
    """Issue a short-lived approval without printing the token."""
    from core.enforcement import (
        effective_approval_fingerprint,
        resolve_effective_action,
    )
    from core.profiles import AssetRegistry, ProfileCatalog

    authority = _approval_authority(args.approval_spent_dir)
    if authority is None:
        raise SystemExit("HARNESS_APPROVAL_SECRET is required")

    catalog = ProfileCatalog.from_yaml(args.profiles)
    assets = AssetRegistry.from_yaml(args.assets)
    profile = catalog.get(args.profile_id)
    action = resolve_effective_action(catalog, assets, args.asset_id, args.profile_id)
    if not profile.approval_required:
        raise SystemExit("profile does not require approval")

    token = authority.issue(
        args.asset_id,
        args.profile_id,
        effective_approval_fingerprint(action),
        ttl_seconds=args.ttl_seconds,
        delay_seconds=args.delay_seconds,
        credential_id=args.credential_id,
        action_fingerprint=action.fingerprint,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    print(f"approval written : {output}")
    if args.delay_seconds:
        print(f"usable in        : {args.delay_seconds}s (cooling-off)")
        print(f"usable window    : {args.ttl_seconds}s after that")
    else:
        print(f"expires in       : {args.ttl_seconds}s")
    return 0


def cmd_replay(args) -> int:
    """Reproducibility check: recompute the verdict PURELY from the stored trace,
    touching nothing live. Proves a run is auditable after the fact."""
    from core.replay import replay_run

    run_dir = Path(args.run_dir)
    recomputed = replay_run(run_dir)
    stored = json.loads((run_dir / "result.json").read_text())
    match = recomputed["completed"] == stored["completed"]
    print(f"stored   completed = {stored['completed']}")
    print(f"replayed completed = {recomputed['completed']}")
    print("MATCH ✅" if match else "MISMATCH ❌ (result is not reproducible from trace)")
    return 0 if match else 1


def cmd_t3_state(args) -> int:
    """Produce canonical structured SSH/22 evidence; no credential or SSH login is used."""
    if not args.confirm_lab_probe:
        raise SystemExit("refusing network probe without --confirm-lab-probe")
    from core.investigation.ssh_reachability import (
        HexStrikeSshReachabilityExecutor,
        produce_ssh_reachability_state,
    )
    from core.safety import KillSwitch

    run_dir = produce_ssh_reachability_state(
        asset_id=args.asset_id,
        assets_path=args.assets,
        profiles_path=args.profiles,
        policy_path=args.policy,
        runs_root=args.runs_root,
        executor=HexStrikeSshReachabilityExecutor(),
        kill_switch=KillSwitch(Path(args.kill_switch_file)),
        assurance_profile=args.assurance_profile,
    )
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    print(f"run dir : {run_dir}")
    print(f"state   : {run_dir / 'investigation_state.json'}")
    print(f"status  : {result['status']}")
    return 0 if result["completed"] else 1


def _t3_proposal(args):
    if args.profile_id == "windows-host-enumeration-readonly":
        from core.t3.enumeration import T3BAgentProposal

        return T3BAgentProposal(
            asset_id=args.asset_id,
            profile_id=args.profile_id,
        )
    from core.t3.access import (
        T3AccessProposal,
        T3AuthorizedAccessProposal,
    )

    if args.profile_id == "t3-authorized-access-bounded":
        return T3AuthorizedAccessProposal(
            asset_id=args.asset_id,
            profile_id=args.profile_id,
        )

    return T3AccessProposal(
        asset_id=args.asset_id,
        profile_id=args.profile_id,
        objective=args.objective,
        command_ids=args.command_id,
    )


def _t3_composition(args):
    if args.profile_id == "windows-host-enumeration-readonly":
        from core.artifacts import ArtifactSealAuthority
        from core.t3.enumeration_runtime import compose_t3b_runtime

        if not args.prerequisite_run_dir:
            raise SystemExit("T3-B requires --prerequisite-run-dir")
        if args.command_id:
            raise SystemExit(
                "T3-B command selection is not supported; the canonical five-action set is fixed"
            )
        artifact_approval_authority = _approval_authority(args.approval_spent_dir)
        if artifact_approval_authority is None:
            raise SystemExit("HARNESS_APPROVAL_SECRET is required for artifact verification")
        try:
            return compose_t3b_runtime(
                proposal=_t3_proposal(args),
                runtime_config_path=args.runtime_config,
                assets_path=args.assets,
                profiles_path=args.profiles,
                policy_path=args.policy,
                prerequisite_run_dir=args.prerequisite_run_dir,
                artifact_authority=ArtifactSealAuthority.from_approval_authority(
                    artifact_approval_authority
                ),
            )
        except Exception as exc:
            raise SystemExit("T3-B runtime configuration is not ready") from exc
    from core.t3.runtime import compose_t3_runtime

    if args.profile_id == "t3-authorized-access-bounded" and args.command_id:
        raise SystemExit(
            "authorized T3-A command selection is not supported; "
            "the canonical three-action set is fixed"
        )
    if not args.investigation_state:
        raise SystemExit("T3-A requires --investigation-state")
    try:
        return compose_t3_runtime(
            proposal=_t3_proposal(args),
            runtime_config_path=args.runtime_config,
            assets_path=args.assets,
            profiles_path=args.profiles,
            policy_path=args.policy,
            investigation_state_path=args.investigation_state,
        )
    except Exception as exc:  # noqa: BLE001 - operator paths/details stay private
        raise SystemExit("T3-A runtime configuration is not ready") from exc


def cmd_t3_ready(args) -> int:
    """Validate all pre-approval controls without resolving credentials or connecting."""
    import os
    import stat
    from dataclasses import asdict
    from datetime import datetime, timedelta, timezone
    from pathlib import Path
    from urllib.parse import urlparse

    from core.t3.assurance import (
        COMMON_CHECKS,
        DEFERRED_CHECKS,
        evaluate_readiness,
    )

    composition = _t3_composition(args)
    endpoint = urlparse(composition.config.hexstrike_url)
    common = dict.fromkeys(COMMON_CHECKS, True)
    common["hexstrike_loopback_endpoint"] = (
        endpoint.scheme == "http"
        and endpoint.hostname == "127.0.0.1"
        and endpoint.port == 8888
        and not endpoint.username
        and not endpoint.password
        and endpoint.path in {"", "/"}
        and not endpoint.query
        and not endpoint.fragment
    )
    secret = os.environ.get("HARNESS_EXECUTION_PERMIT_SECRET", "")
    secret_file = Path("/etc/agent-eval-harness/t3-permit.env")
    unit_file = Path("/etc/systemd/system/hexstrike-t3.service")
    hardened_attestation_file = Path("/etc/agent-eval-harness/hardened-readiness.json")
    try:
        secret_isolated = (
            secret_file.stat().st_uid == 0 and stat.S_IMODE(secret_file.stat().st_mode) == 0o600
        )
    except OSError:
        secret_isolated = False
    try:
        unit = unit_file.read_text(encoding="utf-8")
    except OSError:
        unit = ""
    try:
        attestation_info = hardened_attestation_file.stat()
        attestation = json.loads(hardened_attestation_file.read_text(encoding="utf-8"))
        verified_at = datetime.fromisoformat(attestation["verified_at"])
        uid_enforcement_verified = (
            attestation_info.st_uid == 0
            and stat.S_IMODE(attestation_info.st_mode) == 0o600
            and set(attestation) == {"uid_network_enforcement", "verified_at"}
            and attestation["uid_network_enforcement"] is True
            and verified_at.tzinfo is not None
            and verified_at.utcoffset() is not None
            and datetime.now(timezone.utc) - timedelta(minutes=15)
            <= verified_at
            <= datetime.now(timezone.utc) + timedelta(seconds=30)
        )
    except (KeyError, OSError, TypeError, ValueError):
        uid_enforcement_verified = False
    hardened = dict.fromkeys(DEFERRED_CHECKS, False)
    hardened.update(
        {
            "signed_execution_permit": len(secret.encode()) >= 32,
            "approval_signing_key_isolation": secret_isolated,
            "downstream_delegation_token": len(secret.encode()) >= 32,
            "dedicated_executor_identity": "User=hexstrike" in unit,
            "hardened_systemd_deployment": (
                "NoNewPrivileges=true" in unit and "ProtectSystem=strict" in unit
            ),
            # This exact root-owned attestation is written only after the
            # privileged verifier has inspected the live kernel rule set.
            "uid_network_enforcement": uid_enforcement_verified,
        }
    )
    report = evaluate_readiness(
        composition.assurance,
        common=common,
        hardened=hardened,
    )
    print(
        json.dumps(
            {
                "assurance_profile": report.profile.value,
                "assurance_config_source": report.trusted_source,
                "ready": report.ready,
                "ready_with_profile_skips": report.ready_with_profile_skips,
                "production_ready": (report.ready and report.profile.value == "hardened"),
                "aisvs_level_2_or_3_compliance_claimed": False,
                "checks": [
                    {
                        **asdict(item),
                        "status": item.status.value,
                        "profile": item.profile.value,
                    }
                    for item in report.checks
                ],
            },
            indent=2,
        )
    )
    if not report.ready:
        return 1
    if args.profile_id == "windows-host-enumeration-readonly":
        print("T3-B readiness: ready")
        print(f"stage   : {composition.bindings.stage_id}")
        print(f"asset   : {composition.plan.asset_id}")
        print(f"profile : {composition.bindings.profile_id}")
        print(f"commands: {', '.join(composition.bindings.command_ids)}")
        print(f"prerequisite: {composition.prerequisite.evidence_ref}")
        print("limits  : 5 commands, 1 session, 15s/command, 60s total")
        print(f"registry: {composition.bindings.registry_digest}")
        print(f"runtime : {composition.bindings.runtime_binding_fingerprint}")
        print("network : not contacted")
        print("credential: not resolved")
        return 0
    print("T3-A readiness: ready")
    print(f"asset   : {composition.request.source_asset_id}")
    print(f"profile : {composition.request.capability_id}")
    print(f"commands: {len(composition.request.command_scope)} fixed observation(s)")
    print("network : not contacted")
    print("credential: not resolved")
    return 0


def _t3_approval_summary(args, composition) -> dict:
    if args.profile_id == "windows-host-enumeration-readonly":
        return {
            "asset_id": composition.plan.asset_id,
            "resolved_target_identity": composition.bindings.resolved_target_identity,
            "profile_id": composition.bindings.profile_id,
            "stage": composition.bindings.stage_id,
            "action_ids": list(composition.bindings.command_ids),
            "justification": composition.bindings.justification,
            "runtime_binding_fingerprint": (composition.bindings.runtime_binding_fingerprint),
            "assurance_profile": composition.assurance.profile.value,
        }
    return {
        "asset_id": composition.request.source_asset_id,
        "resolved_target_identity": canonical_digest(
            {
                "asset_id": composition.request.source_asset_id,
                "target": composition.assets.resolve(composition.request.source_asset_id)["target"],
            }
        ),
        "profile_id": composition.request.capability_id,
        "stage": composition.request.stage.value,
        "action_ids": list(composition.request.command_scope),
        "justification": composition.request.written_justification,
        "runtime_binding_fingerprint": composition.runtime_binding_fingerprint,
        "assurance_profile": composition.assurance.profile.value,
    }


def cmd_t3_scope(args) -> int:
    """Display the exact canonical scope without issuing an approval."""
    composition = _t3_composition(args)
    print("Canonical approval request (unsigned):")
    print(json.dumps(_t3_approval_summary(args, composition), indent=2, sort_keys=True))
    return 0


def cmd_t3_approve(args) -> int:
    """Issue the exact action/session-bound T3-A approval."""
    composition = _t3_composition(args)
    print("Canonical approval request:")
    print(json.dumps(_t3_approval_summary(args, composition), indent=2, sort_keys=True))
    authority = _approval_authority(args.approval_spent_dir)
    if authority is None:
        raise SystemExit("HARNESS_APPROVAL_SECRET is required")
    token = authority.issue(
        (
            composition.plan.asset_id
            if args.profile_id == "windows-host-enumeration-readonly"
            else composition.request.source_asset_id
        ),
        (
            composition.bindings.profile_id
            if args.profile_id == "windows-host-enumeration-readonly"
            else composition.request.capability_id
        ),
        (
            composition.bindings.fingerprint
            if args.profile_id == "windows-host-enumeration-readonly"
            else composition.fingerprint
        ),
        ttl_seconds=args.ttl_seconds,
        credential_id=composition.config.credential_ref,
        action_fingerprint=(
            composition.bindings.fingerprint
            if args.profile_id == "windows-host-enumeration-readonly"
            else composition.fingerprint
        ),
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    stage = "T3-B" if args.profile_id == "windows-host-enumeration-readonly" else "T3-A"
    print(f"{stage} approval written: {output}")
    return 0


def cmd_t3_run(args) -> int:
    """Compose and invoke the dedicated Controller route; never call SSH directly."""
    from core.investigation.models import InvestigationState
    from core.t3.runtime import (
        T3_ENABLEMENT_ENV,
        build_t3_controller_and_executor,
    )

    composition = _t3_composition(args)
    authority = _approval_authority(args.approval_spent_dir)
    token = (
        _read_token_file(args.approval_token_file)
        if getattr(args, "approval_token_file", None)
        else ""
    )
    if args.profile_id == "windows-host-enumeration-readonly":
        from core.safety import KillSwitch
        from core.t3.enumeration_runtime import execute_t3b_composition
        from core.t3.runtime import T3_ENABLEMENT_ENV

        if authority is None:
            raise SystemExit("HARNESS_APPROVAL_SECRET is required only for artifact sealing")
        if os.environ.get(T3_ENABLEMENT_ENV) != "true":
            raise SystemExit("T3-B lab execution is disabled")
        run_dir = execute_t3b_composition(
            composition,
            authority=authority,
            token=token,
            runs_root=args.runs_root,
            kill_switch=KillSwitch(Path(args.kill_switch_file)),
        )
        result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
        print(f"run dir : {run_dir}")
        print(f"status  : {result['status']}")
        return 0 if result["completed"] else 1
    controller, executor = build_t3_controller_and_executor(
        composition=composition,
        runs_root=args.runs_root,
        approval_authority=authority,
        kill_switch_path=args.kill_switch_file,
        enablement=os.environ.get(T3_ENABLEMENT_ENV),
    )
    run_dir = controller.run_t3_action(
        composition.request,
        InvestigationState.model_validate_json(
            Path(args.investigation_state).read_text(encoding="utf-8")
        ),
        executor,
        token,
    )
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    print(f"run dir : {run_dir}")
    print(f"status  : {result['status']}")
    return 0 if result["completed"] else 1


def cmd_t3_unified_run(args) -> int:
    """Submit one protected, server-bound unified action without exposing secrets."""
    import requests

    from core.t3.poc_approval import ApprovalStore
    from core.t3.poc_runner import load_authorization, run
    from core.t3.poc_runtime import load_runtime

    try:
        runtime = load_runtime(args.runtime_file)
        authorization_id = load_authorization(args.authorization_file)
        action_id = ApprovalStore(runtime.approval_database).inspect_pending(
            authorization_id,
            "asset:winsrv2025-01",
            str(runtime.runtime_revision),
            runtime.digest,
        )
        if action_id not in runtime.action_policy["enabled_action_ids"]:
            raise ValueError("action_not_enabled")
        result = run(
            runtime,
            authorization_id=authorization_id,
            action_id=action_id,
            session=requests.Session(),
        )
    except Exception as exc:
        allowed = {
            "action_not_enabled",
            "authorization_rejected",
            "execution_denied",
            "kill_switch_engaged",
            "kill_switch_state_invalid",
            "prerequisite_not_satisfied",
            "protected authorization invalid",
            "protected runtime invalid",
        }
        code = str(exc) if str(exc) in allowed else "unified_execution_failed"
        raise SystemExit(code) from None
    print(f"schema  : {result['schema_version']}")
    print(f"action  : {result['action_id']}")
    print(f"status  : {result['status']}")
    print(f"runtime : {result['runtime_digest']}")
    print(f"evidence: {result['evidence_ref']}")
    return 0 if result["status"] == "completed" else 1


def _cmd_t3_unified_authorize(args, action_id: str) -> int:
    """Create one action-bound approval and owner-only authorization file."""
    from core.t3.poc_approval import ApprovalStore
    from core.t3.poc_runtime import load_runtime

    output = Path(args.authorization_file)
    descriptor = -1
    try:
        runtime = load_runtime(args.runtime_file)
        if output.exists() or output.is_symlink():
            raise ValueError("authorization_output_exists")
        if Path(runtime.kill_switch_file).exists():
            raise ValueError("kill_switch_engaged")
        authorization_id = ApprovalStore(runtime.approval_database).issue(
            action_id,
            "asset:winsrv2025-01",
            str(runtime.runtime_revision),
            runtime.digest,
            approving_uid=os.geteuid(),
        )
        descriptor = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump({"authorization_id": authorization_id}, handle)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception as exc:
        allowed = {
            "authorization_output_exists",
            "kill_switch_engaged",
            "protected runtime invalid",
        }
        code = str(exc) if str(exc) in allowed else "authorization_creation_failed"
        raise SystemExit(code) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    print(f"approval: created for {action_id}")
    print(f"authorization file: {output}")
    return 0


def cmd_t3_unified_authorize_reachability(args) -> int:
    return _cmd_t3_unified_authorize(args, "t3a.ssh22_reachability.v1")


def cmd_t3_unified_authorize_identity(args) -> int:
    return _cmd_t3_unified_authorize(args, "windows.ssh.readonly_identity.v1")


def _add_t3_proposal_arguments(parser) -> None:
    parser.add_argument("--asset-id", required=True)
    parser.add_argument(
        "--profile-id",
        required=True,
        choices=[
            "t3-access-bounded",
            "t3-authorized-access-bounded",
            "windows-host-enumeration-readonly",
        ],
    )
    parser.add_argument("--objective")
    parser.add_argument(
        "--command-id",
        action="append",
        choices=[
            "current_identity",
            "host_identity",
            "privilege_context",
            "windows_os_version",
            "windows_network_configuration",
            "windows_listening_ports",
            "windows_running_services",
            "windows_installed_hotfixes",
        ],
        help=(
            "only for vulnerability-driven t3-access-bounded; authorized T3-A and T3-B "
            "use fixed canonical action sets"
        ),
    )
    parser.add_argument("--runtime-config", required=True)
    parser.add_argument("--assets", default="assets.yaml")
    parser.add_argument("--profiles", default="profiles.yaml")
    parser.add_argument("--policy", default="policy.yaml")
    parser.add_argument(
        "--investigation-state",
        help="required for T3-A; unused for T3-B, whose prerequisite is the original T3-A run",
    )
    parser.add_argument(
        "--prerequisite-run-dir",
        help="original verified T3-A run directory; required only for T3-B",
    )
    parser.add_argument("--approval-spent-dir", default="config/local/approval-spent")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="run a case with an agent")
    p_run.add_argument("case", help="path to a case YAML")
    p_run.add_argument("--agent", default="mock", help="mock | hexstrike")
    p_run.add_argument("--runs-root", default="runs")
    p_run.add_argument(
        "--policy", default=None, help="path to policy.yaml (enables the policy gate)"
    )
    p_run.add_argument(
        "--profiles", default=None, help="path to profiles.yaml (profile-driven mode)"
    )
    p_run.add_argument("--assets", default=None, help="path to assets.yaml (asset_id resolver)")
    p_run.add_argument(
        "--max-tokens-total",
        type=int,
        default=20_000,
        help="maximum cumulative LLM input+output tokens",
    )
    p_run.add_argument(
        "--max-cost-usd",
        type=float,
        default=None,
        help="maximum cumulative LLM cost; defaults to policy max_cost_usd",
    )
    p_run.add_argument(
        "--approval-token-file",
        default=None,
        help="0600 file containing a single-use approval token",
    )
    p_run.add_argument(
        "--approval-spent-dir",
        default="config/local/approval-spent",
        help="local directory for consumed-token markers",
    )
    p_run.add_argument(
        "--job-create-token-file",
        default=None,
        help="0600 file containing the HexStrike job creation capability",
    )
    p_run.add_argument(
        "--kill-switch-file",
        default="config/local/KILL",
        help="execution stops when this file exists",
    )
    p_run.add_argument(
        "--investigation-state",
        default=None,
        help="resume Claude from a prior run's investigation_state.json",
    )
    p_run.set_defaults(func=cmd_run)

    p_approve = sub.add_parser("approve", help="issue a short-lived single-use approval")
    p_approve.add_argument("--profiles", required=True)
    p_approve.add_argument("--assets", required=True)
    p_approve.add_argument("--asset-id", required=True)
    p_approve.add_argument("--profile-id", required=True)
    p_approve.add_argument("--ttl-seconds", type=int, default=300)
    p_approve.add_argument(
        "--delay-seconds",
        type=int,
        default=0,
        help="cooling-off period before the approval becomes usable (0-86400)",
    )
    p_approve.add_argument(
        "--credential-id",
        default="",
        help="optional named T3 credential id to bind to this approval token",
    )
    p_approve.add_argument("--output", required=True)
    p_approve.add_argument("--approval-spent-dir", default="config/local/approval-spent")
    p_approve.set_defaults(func=cmd_approve)

    p_replay = sub.add_parser("replay", help="recompute a run's verdict from its trace")
    p_replay.add_argument("run_dir", help="path to runs/<run_id>")
    p_replay.set_defaults(func=cmd_replay)

    def cmd_agent_demo(args) -> int:
        from core.orchestration.demo import run_demo
        from core.orchestration.planner import (
            DeterministicPlanner,
            OllamaPlanner,
            OllamaPlannerError,
        )

        try:
            planner = OllamaPlanner() if args.planner == "ollama" else DeterministicPlanner()
        except OllamaPlannerError as exc:
            raise SystemExit(str(exc)) from None
        print(
            json.dumps(
                run_demo(args.fixture, planner=planner, asset_id=args.asset_id, task=args.task),
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    def cmd_ollama_check(args) -> int:
        from core.orchestration.planner import OllamaPlanner, OllamaPlannerError

        try:
            planner = OllamaPlanner()
            decision = planner.check()
        except OllamaPlannerError as exc:
            raise SystemExit(str(exc)) from None
        print(
            json.dumps(
                {
                    "connected": True,
                    "model": planner.model,
                    "schema_conforming_decision": decision.model_dump(exclude_none=True),
                    "complete_agent_test": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    def cmd_agent_run(args) -> int:
        import time

        from core.orchestration.catalog import CapabilityCatalog
        from core.orchestration.live import LiveHexStrikeExecutor
        from core.orchestration.models import RunStatus
        from core.orchestration.orchestrator import Orchestrator
        from core.orchestration.planner import OllamaPlanner, OllamaPlannerError
        from core.policy import Policy
        from core.profiles import AssetRegistry, ProfileCatalog
        from core.safety import KillSwitch

        if args.executor != "hexstrike" or args.planner != "ollama":
            raise SystemExit("the first live slice requires --planner ollama --executor hexstrike")
        token = _read_token_file(args.job_create_token_file, "job create token")
        try:
            profiles = ProfileCatalog.from_yaml(args.profiles)
            full_catalog = CapabilityCatalog.from_yaml(args.capabilities, profiles)
            catalog = CapabilityCatalog(
                {
                    capability_id: full_catalog.get(capability_id)
                    for capability_id in (
                        "network.service_discovery",
                        "ssh.posture_check",
                        "rdp.posture_check",
                        "smb.posture_check",
                    )
                }
            )
            assets = AssetRegistry.from_yaml(args.assets)
            policy = Policy.from_yaml(args.policy)
            planner = OllamaPlanner()
            executor = LiveHexStrikeExecutor(
                profiles=profiles,
                assets=assets,
                policy=policy,
                job_create_token=token,
                kill_switch=KillSwitch(Path(args.kill_switch_file)),
                runs_root=args.runs_root,
                base_url=os.environ.get("HEXSTRIKE_BASE_URL", "http://127.0.0.1:8888"),
                timeout_seconds=int(os.environ.get("HEXSTRIKE_TIMEOUT_SECONDS", "90")),
            )
        except (OSError, ValueError, OllamaPlannerError) as exc:
            raise SystemExit(str(exc)) from None
        if not executor.health():
            raise SystemExit("HexStrike health check failed at http://127.0.0.1:8888/health")

        run_id = f"agent-live-{time.time_ns()}"
        audit_events: list[dict[str, object]] = []
        orchestrator = Orchestrator(
            catalog=catalog,
            profiles=profiles,
            assets=assets,
            policy=policy,
            planner=planner,
            executor=executor,
            kill_switch=KillSwitch(Path(args.kill_switch_file)).engaged,
            audit=audit_events.append,
        )
        run = orchestrator.start(
            run_id=run_id,
            principal="local-operator",
            asset_id=args.asset_id,
            task=args.task,
        )
        for _ in range(orchestrator.budgets.max_steps):
            run = orchestrator.advance(run)
            if run.status is not RunStatus.RUNNING:
                break
        if run.status is RunStatus.SUCCEEDED and run.failed:
            run.status = RunStatus.COMPLETED_WITH_FAILURES
        run_dir = Path(args.runs_root) / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "orchestration-audit.json").write_text(
            json.dumps(audit_events, indent=2, sort_keys=True), encoding="utf-8"
        )
        result = {
            "live_hexstrike": True,
            "hexstrike_health": executor.health_succeeded,
            "run_id": run_id,
            "run_dir": str(run_dir),
            "status": run.status.value,
            "stop_reason": run.stop_reason,
            "capability_sequence": run.executed,
            "attempted_capability_sequence": run.planned,
            "failed_capability_sequence": run.failed,
            "job_id": executor.last_job_id,
            "job_status": executor.last_job_status,
            "job_state_sequence": executor.job_states,
            "executor_error": executor.last_error,
            "executions": executor.executions,
            "evidence_ids": [item for obs in run.observations for item in obs.evidence_ids],
            "observations": [item.model_dump(mode="json") for item in run.observations],
            "trace_path": executor.last_trace_path,
        }
        (run_dir / "orchestration-result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if run.status is RunStatus.SUCCEEDED and run.executed else 1

    p_agent_demo = sub.add_parser(
        "agent-demo", help="run the policy path against deterministic offline fixtures"
    )
    p_agent_demo.add_argument("--fixture", choices=("windows", "web-only"), required=True)
    p_agent_demo.add_argument(
        "--planner", choices=("deterministic", "ollama"), default="deterministic"
    )
    p_agent_demo.add_argument("--executor", choices=("fixture",), default="fixture")
    p_agent_demo.add_argument("--asset-id", default="asset:offline-demo")
    p_agent_demo.add_argument("--task", default="Assess the approved offline fixture")
    p_agent_demo.set_defaults(func=cmd_agent_demo)

    p_ollama_check = sub.add_parser("ollama-check", help="check Ollama and planner schema only")
    p_ollama_check.set_defaults(func=cmd_ollama_check)

    p_agent_run = sub.add_parser("agent-run", help="run the first live HexStrike slice")
    p_agent_run.add_argument("--planner", choices=("ollama",), required=True)
    p_agent_run.add_argument("--executor", choices=("hexstrike",), required=True)
    p_agent_run.add_argument("--asset-id", required=True)
    p_agent_run.add_argument("--task", required=True)
    p_agent_run.add_argument("--assets", default="config/local/assets.yaml")
    p_agent_run.add_argument("--profiles", default="profiles.yaml")
    p_agent_run.add_argument("--policy", default="config/local/policy.yaml")
    p_agent_run.add_argument("--capabilities", default="capabilities.yaml")
    p_agent_run.add_argument("--job-create-token-file", default="config/local/job-create.token")
    p_agent_run.add_argument("--kill-switch-file", default="config/local/KILL")
    p_agent_run.add_argument("--runs-root", default="runs")
    p_agent_run.set_defaults(func=cmd_agent_run)

    p_t3_state = sub.add_parser(
        "t3-state",
        help="produce canonical Windows TCP/22 reachability investigation state",
    )
    p_t3_state.add_argument("--asset-id", required=True)
    p_t3_state.add_argument("--assets", default="assets.yaml")
    p_t3_state.add_argument("--profiles", default="profiles.yaml")
    p_t3_state.add_argument("--policy", default="policy.yaml")
    p_t3_state.add_argument("--runs-root", default="runs")
    p_t3_state.add_argument("--kill-switch-file", default="config/local/KILL")
    p_t3_state.add_argument(
        "--assurance-profile",
        choices=("poc", "hardened"),
        default="hardened",
    )
    p_t3_state.add_argument(
        "--confirm-lab-probe",
        action="store_true",
        help="confirm one fixed TCP/22 probe to the registered isolated-lab asset",
    )
    p_t3_state.set_defaults(func=cmd_t3_state)

    p_t3_ready = sub.add_parser(
        "t3-ready",
        help="validate T3-A operator configuration without credentials or network",
    )
    _add_t3_proposal_arguments(p_t3_ready)
    p_t3_ready.set_defaults(func=cmd_t3_ready)

    p_t3_scope = sub.add_parser(
        "t3-scope",
        help="display the canonical T3 approval scope without issuing an approval",
    )
    _add_t3_proposal_arguments(p_t3_scope)
    p_t3_scope.set_defaults(func=cmd_t3_scope)

    p_t3_approve = sub.add_parser(
        "t3-approve",
        help="issue an action- and session-bound T3-A approval",
    )
    _add_t3_proposal_arguments(p_t3_approve)
    p_t3_approve.add_argument("--ttl-seconds", type=int, default=300)
    p_t3_approve.add_argument("--output", required=True)
    p_t3_approve.set_defaults(func=cmd_t3_approve)

    p_t3_run = sub.add_parser(
        "t3-run",
        help="run one approved bounded T3-A SSH assessment",
    )
    _add_t3_proposal_arguments(p_t3_run)
    p_t3_run.add_argument(
        "--approval-token-file",
        help="deprecated and ignored for T3-A/T3-B; retained for CLI compatibility",
    )
    p_t3_run.add_argument("--runs-root", default="runs")
    p_t3_run.add_argument("--kill-switch-file", default="config/local/KILL")
    p_t3_run.set_defaults(func=cmd_t3_run)

    p_unified = sub.add_parser(
        "t3-unified-run",
        help="submit one protected unified T3 authorization to loopback HexStrike",
    )
    p_unified.add_argument("--runtime-file", required=True)
    p_unified.add_argument("--authorization-file", required=True)
    p_unified.set_defaults(func=cmd_t3_unified_run)

    for name, help_text, handler in (
        (
            "t3-unified-authorize-reachability",
            "create one protected TCP/22 reachability approval",
            cmd_t3_unified_authorize_reachability,
        ),
        (
            "t3-unified-authorize-identity",
            "create one protected Windows read-only identity approval",
            cmd_t3_unified_authorize_identity,
        ),
    ):
        approval_parser = sub.add_parser(name, help=help_text)
        approval_parser.add_argument("--runtime-file", required=True)
        approval_parser.add_argument("--authorization-file", required=True)
        approval_parser.set_defaults(func=handler)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
