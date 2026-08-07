"""Offline deterministic orchestration demo; no network or live credentials."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.enforcement import SERVICE_DISCOVERY_PORTS
from core.orchestration.catalog import CapabilityCatalog
from core.orchestration.models import ApprovalGrant, ExecutionResult, Fact, RunStatus
from core.orchestration.orchestrator import Orchestrator
from core.orchestration.planner import DeterministicPlanner, Planner
from core.policy import Policy
from core.profiles import AssetRegistry, ProfileCatalog


class OfflineExecutor:
    def __init__(self, branch: str):
        self.branch: str = branch
        self.calls: list[str] = []

    def execute(self, capability, run):
        self.calls.append(capability.capability_id)
        if capability.capability_id == "network.service_discovery":
            ports = (22, 80, 139, 445, 3389) if self.branch == "windows" else (80, 443)
            names = {
                22: "ssh",
                80: "http",
                139: "netbios-ssn",
                443: "https",
                445: "microsoft-ds",
                3389: "ms-wbt-server",
            }
            output = "\n".join(f"{p}/tcp open {names[p]}" for p in ports) + "\nNmap done: fixture"
        else:
            output = "offline fixture completed"
        return ExecutionResult(
            status="succeeded",
            output=output,
            facts=(
                [
                    Fact(type="scanned_port", values={"port": int(port), "protocol": "tcp"})
                    for port in SERVICE_DISCOVERY_PORTS.split(",")
                ]
                if capability.capability_id == "network.service_discovery"
                else []
            ),
            evidence_ids=[f"evidence:demo:{len(self.calls)}"],
            evidence_types=set(),
        )


def run_demo(
    branch: str,
    *,
    planner: Planner | None = None,
    asset_id: str = "asset:offline-demo",
    task: str = "Assess the approved offline fixture",
) -> dict:
    profiles = ProfileCatalog.from_yaml("profiles.yaml")
    catalog = CapabilityCatalog.from_yaml("capabilities.yaml", profiles)
    assets = AssetRegistry(
        {
            asset_id: {
                "asset_type": "host",
                "target": "192.0.2.10",
                "ports": "22,80,139,443,445,3389",
                "tool_args": {
                    "httpx": {"ports": "80"},
                    "gobuster": {"ports": "80"},
                    "nuclei": {"ports": "80"},
                },
            }
        }
    )
    executor = OfflineExecutor(branch)
    events: list[dict] = []
    orchestrator = Orchestrator(
        catalog=catalog,
        profiles=profiles,
        assets=assets,
        policy=Policy.from_yaml("policy.yaml"),
        planner=planner or DeterministicPlanner(),
        executor=executor,
        kill_switch=lambda: False,
        audit=events.append,
    )
    run = orchestrator.start(
        run_id=f"demo-{branch}",
        principal="offline-demo",
        asset_id=asset_id,
        task=task,
    )
    for index in range(40):
        run = orchestrator.advance(run)
        if run.status is RunStatus.APPROVAL_REQUIRED:
            item = catalog.get(run.pending_capability or "")
            approval = ApprovalGrant(
                token_id=f"offline-{index}",
                principal=run.principal,
                run_id=run.run_id,
                asset_id=run.asset_id,
                capability_id=item.capability_id,
                stage=item.phase,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
            )
            run = orchestrator.advance(run, approval)
        if run.status not in {RunStatus.RUNNING, RunStatus.APPROVAL_REQUIRED}:
            break
    return {
        "offline_fixture": True,
        "status": run.status.value,
        "sequence": executor.calls,
        "observations": [item.model_dump(mode="json") for item in run.observations],
        "stop_reason": run.stop_reason,
        "audit_events": len(events),
    }
