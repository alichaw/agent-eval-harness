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


def _t3_proposal(args):
    if args.profile_id == "windows-host-enumeration-readonly":
        from core.t3.enumeration import T3BProposal

        return T3BProposal(
            asset_id=args.asset_id,
            profile_id=args.profile_id,
            objective=args.objective,
            command_ids=args.command_id,
        )
    from core.t3.access import T3AccessProposal

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
    composition = _t3_composition(args)
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


def cmd_t3_approve(args) -> int:
    """Issue the exact action/session-bound T3-A approval."""
    composition = _t3_composition(args)
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
    if authority is None:
        raise SystemExit("HARNESS_APPROVAL_SECRET is required")
    token = _read_token_file(args.approval_token_file)
    if args.profile_id == "windows-host-enumeration-readonly":
        from core.safety import KillSwitch
        from core.t3.enumeration import ParamikoT3BTransport
        from core.t3.enumeration_runtime import execute_t3b_composition
        from core.t3.runtime import T3_ENABLEMENT_ENV

        if os.environ.get(T3_ENABLEMENT_ENV) != "true":
            raise SystemExit("T3-B lab execution is disabled")
        run_dir = execute_t3b_composition(
            composition,
            authority=authority,
            token=token,
            transport=ParamikoT3BTransport(),
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
    parser.add_argument("--objective", required=True)
    parser.add_argument(
        "--command-id",
        required=True,
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
    )
    parser.add_argument("--runtime-config", required=True)
    parser.add_argument("--assets", default="assets.yaml")
    parser.add_argument("--profiles", default="profiles.yaml")
    parser.add_argument("--policy", default="policy.yaml")
    parser.add_argument("--investigation-state", required=True)
    parser.add_argument(
        "--prerequisite-run-dir",
        help="original verified T3-A run directory; required only for T3-B",
    )


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

    p_t3_ready = sub.add_parser(
        "t3-ready",
        help="validate T3-A operator configuration without credentials or network",
    )
    _add_t3_proposal_arguments(p_t3_ready)
    p_t3_ready.set_defaults(func=cmd_t3_ready)

    p_t3_approve = sub.add_parser(
        "t3-approve",
        help="issue an action- and session-bound T3-A approval",
    )
    _add_t3_proposal_arguments(p_t3_approve)
    p_t3_approve.add_argument("--ttl-seconds", type=int, default=300)
    p_t3_approve.add_argument("--output", required=True)
    p_t3_approve.add_argument("--approval-spent-dir", default="config/local/approval-spent")
    p_t3_approve.set_defaults(func=cmd_t3_approve)

    p_t3_run = sub.add_parser(
        "t3-run",
        help="run one approved bounded T3-A SSH assessment",
    )
    _add_t3_proposal_arguments(p_t3_run)
    p_t3_run.add_argument("--approval-token-file", required=True)
    p_t3_run.add_argument("--approval-spent-dir", default="config/local/approval-spent")
    p_t3_run.add_argument("--runs-root", default="runs")
    p_t3_run.add_argument("--kill-switch-file", default="config/local/KILL")
    p_t3_run.set_defaults(func=cmd_t3_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
