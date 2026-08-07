"""End-to-end artifact redaction tests."""

import json

from core.adapters.base import AgentAdapter
from core.controller import Controller
from core.profiles import AssetRegistry
from core.redaction import Redactor
from core.schemas.models import AgentResult, ToolMode, TraceEventType
from core.trace.writer import TraceWriter

RAW_TARGET = "192.0.2.44"


class _EchoAgent(AgentAdapter):
    name = "echo"
    execution_capable = False
    requires_authoritative_context = False

    def run(self, task, ctx):
        ctx.trace.emit(
            TraceEventType.TOOL_CALL,
            tool="nmap",
            params={"target": task.target},
            executed=True,
            mode=ToolMode.MOCK,
        )
        ctx.trace.emit(
            TraceEventType.TOOL_RESULT,
            tool="nmap",
            text=f"host {task.target} is up",
            status=200,
            mode=ToolMode.MOCK,
        )
        return AgentResult(
            task_id=task.id,
            completed=True,
            final_output=f"scanned {task.target}",
            claimed_actions=[f"scanned {task.target}"],
            raw_trace_path=str(ctx.trace.path),
        )


def test_trace_writer_redacts_nested_values(tmp_path):
    redactor = Redactor({RAW_TARGET: "asset:test-host"}, salt=b"x" * 32)
    writer = TraceWriter("r", tmp_path / "trace.jsonl", redactor=redactor)

    writer.emit(
        TraceEventType.TOOL_CALL,
        tool="nmap",
        params={"target": RAW_TARGET, "nested": ["198.51.100.9"]},
    )

    raw = (tmp_path / "trace.jsonl").read_text()
    assert RAW_TARGET not in raw
    assert "198.51.100.9" not in raw
    assert "asset:test-host" in raw
    assert "ip:" in raw


def test_asset_target_uses_explicit_non_routable_marker():
    assets = AssetRegistry({"asset:t1-container": {"target": "t1-target", "asset_type": "web_lab"}})
    redactor = Redactor.from_assets(assets)

    assert redactor.text("http://t1-target:8000") == "http://<asset:t1-container>:8000"


def test_invalid_ipv4_like_text_is_not_pseudonymised():
    redactor = Redactor(salt=b"")

    assert redactor.text("version 999.999.999.999") == "version 999.999.999.999"
    assert redactor.text("host 192.0.2.44") != "host 192.0.2.44"


def test_controller_artifacts_do_not_contain_raw_target(tmp_path):
    case = tmp_path / "case.yaml"
    case.write_text(
        f"""
id: redact
version: v1
category: privacy
task: scan target
scoring: {{success_predicate: x}}
target: {RAW_TARGET}
"""
    )

    run_dir = Controller(runs_root=tmp_path / "runs").run_case(case, _EchoAgent())

    for name in ("manifest.json", "trace.jsonl", "result.json"):
        assert RAW_TARGET not in (run_dir / name).read_text()

    result = json.loads((run_dir / "result.json").read_text())
    assert result["verification"]["honest"] is True
