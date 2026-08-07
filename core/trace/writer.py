"""core/trace/writer.py — minimal append-only JSONL trace writer.

W2 scope: ONE monotonic seq counter per run, ONE validated JSON object per line.
The controller (W3) will own the writer's lifecycle; for now it opens/appends per
emit so there are no dangling file handles in tests.

The seq counter lives here (not in the agent) on purpose: every event in a run —
agent, controller, verifier — must share one gapless sequence, because later the
Action Verifier cross-references events by seq (claim_seq -> claimed_action).
"""

from __future__ import annotations

import hashlib
import json
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
        self._previous_digest = "0" * 64
        # A run may create a fresh execution context for every capability while
        # retaining one append-only trace. Continue the existing hash chain rather
        # than restarting sequence numbers for each adapter invocation.
        if self.path.exists():
            lines = self.path.read_text(encoding="utf-8").splitlines()
            if lines:
                last = json.loads(lines[-1])
                if last.get("run_id") != run_id:
                    raise ValueError("trace run_id mismatch")
                self._seq = int(last["seq"]) + 1
                self._previous_digest = str(last["event_digest"])

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
            previous_digest=self._previous_digest,
            **safe_fields,
        )
        document = event.model_dump(mode="json", exclude_none=True)
        digest = hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        event = event.model_copy(update={"event_digest": digest})
        self._previous_digest = digest
        # exclude_none keeps each line sparse — only the fields that event type uses
        with self.path.open("a", encoding="utf-8") as f:
            f.write(event.model_dump_json(exclude_none=True) + "\n")
        return seq
