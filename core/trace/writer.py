"""core/trace/writer.py — minimal append-only JSONL trace writer.

W2 scope: ONE monotonic seq counter per run, ONE validated JSON object per line.
The controller (W3) will own the writer's lifecycle; for now it opens/appends per
emit so there are no dangling file handles in tests.

The seq counter lives here (not in the agent) on purpose: every event in a run —
agent, controller, verifier — must share one gapless sequence, because later the
Action Verifier cross-references events by seq (claim_seq -> claimed_action).
"""

from __future__ import annotations

import time
from pathlib import Path

from core.redaction import Redactor
from core.schemas.models import TraceEvent, TraceEventType


class TraceWriter:
    def __init__(self, run_id: str, path: Path, redactor: Redactor | None = None):
        self.run_id = run_id
        self.redactor = redactor or Redactor()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0

    def emit(self, type: TraceEventType, **fields) -> int:
        """Build + validate a TraceEvent, append it as one JSONL line, return its seq.

        Returning seq lets callers cross-reference events (e.g. a verification
        event points back at a claimed_action via claim_seq).
        """
        seq = self._seq
        self._seq += 1
        safe_fields = self.redactor.value(fields)
        event = TraceEvent(
            ts=time.time(),
            run_id=self.run_id,
            seq=seq,
            type=type,
            **safe_fields,
        )
        # exclude_none keeps each line sparse — only the fields that event type uses
        with self.path.open("a", encoding="utf-8") as f:
            f.write(event.model_dump_json(exclude_none=True) + "\n")
        return seq
