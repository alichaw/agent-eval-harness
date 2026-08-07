"""Opaque, short-lived, stage-bound identifiers for loopback PoC execution."""

from __future__ import annotations

import hashlib
import time

_STAGE_TAGS = {"T3-A": "a1", "T3-B": "b1", "T3-C": "c1"}


def issue_poc_authorization_id(stage: str, *, now: int | None = None) -> str:
    tag = _STAGE_TAGS.get(stage)
    if tag is None:
        raise ValueError("unknown PoC authorization stage")
    issued_at = int(time.time()) if now is None else now
    if issued_at < 0 or issued_at > 0xFFFFFFFF:
        raise ValueError("PoC authorization timestamp out of range")
    entropy = hashlib.sha256(f"{stage}:{issued_at}:{time.time_ns()}".encode()).hexdigest()[:30]
    return f"{issued_at:08x}{tag}{entropy}"
