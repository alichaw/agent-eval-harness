"""Replay must preserve valid negative security-assessment results."""

from core.replay import replay_run
from core.schemas.models import ToolMode, TraceEventType
from core.trace.writer import TraceWriter


def test_replay_completes_negative_smb_assessment(tmp_path):
    writer = TraceWriter("assessment", tmp_path / "trace.jsonl")
    writer.emit(
        TraceEventType.TOOL_RESULT,
        tool="smb-anonymous-access",
        mode=ToolMode.REAL,
        text="rc=1 assessment_ran=yes",
    )

    replayed = replay_run(tmp_path)

    assert replayed["completed"] is True
    assert replayed["had_error"] is False
