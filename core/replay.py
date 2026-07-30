"""Strict offline trace replay with integrity and authorization validation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from core.schemas.models import ToolMode, TraceEvent, TraceEventType

_ZERO_DIGEST = "0" * 64
_ACCEPTED_RETURN_CODES = {
    "nc": {0, 1},
    "smb-anonymous-access": {0, 1},
    "smb-posture": {0, 1},
    "smb-ms17-010-check": {0, 1},
    "rdp-posture": {0, 1},
}


def _failure(reason: str, events: list[TraceEvent] | None = None) -> dict:
    return {
        "completed": False,
        "valid": False,
        "failure_reason": reason,
        "n_events": len(events or []),
        "had_error": bool(events and any(item.type is TraceEventType.ERROR for item in events)),
        "n_tool_results": sum(item.type is TraceEventType.TOOL_RESULT for item in (events or [])),
    }


def _verify_integrity(events: list[TraceEvent], expected_run_id: str) -> str | None:
    if not events:
        return "empty_trace"
    if any(item.run_id != expected_run_id for item in events):
        return "foreign_run_id"
    if [item.seq for item in events] != list(range(len(events))):
        return "invalid_sequence"
    chained = any(item.event_digest or item.previous_digest for item in events)
    if not chained:
        return None
    previous = _ZERO_DIGEST
    for item in events:
        if not item.event_digest or item.previous_digest != previous:
            return "broken_digest_chain"
        document = item.model_dump(mode="json", exclude_none=True)
        supplied = document.pop("event_digest")
        calculated = hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if supplied != calculated:
            return "broken_digest_chain"
        previous = supplied
    return None


@dataclass(frozen=True)
class ArtifactValidation:
    """Safe, structured result for an immutable run-artifact validation."""

    valid: bool
    code: str
    manifest: dict
    result: dict
    events: tuple[TraceEvent, ...]


def validate_run_artifacts(
    run_dir: str | Path,
    *,
    require_digest_chain: bool = True,
) -> ArtifactValidation:
    """Parse and validate manifest/result/trace as one indivisible audit record."""

    root = Path(run_dir)
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        result = json.loads((root / "result.json").read_text(encoding="utf-8"))
        raw = (root / "trace.jsonl").read_bytes()
        if not raw or not raw.endswith(b"\n"):
            raise ValueError
        lines = raw.splitlines()
        events = tuple(TraceEvent.model_validate_json(line) for line in lines)
    except (OSError, json.JSONDecodeError, ValidationError, ValueError):
        return ArtifactValidation(False, "malformed_or_truncated_artifacts", {}, {}, ())

    run_ids = {manifest.get("run_id"), result.get("run_id")}
    if len(run_ids) != 1 or not all(isinstance(item, str) and item for item in run_ids):
        return ArtifactValidation(False, "artifact_run_id_mismatch", manifest, result, events)
    expected_run_id = manifest["run_id"]
    error = _verify_integrity(list(events), expected_run_id)
    if error:
        return ArtifactValidation(False, error, manifest, result, events)
    if require_digest_chain and any(
        not event.event_digest or not event.previous_digest for event in events
    ):
        return ArtifactValidation(False, "digest_chain_required", manifest, result, events)

    replay = replay_run(root)
    if not replay.get("valid"):
        return ArtifactValidation(
            False, str(replay.get("failure_reason") or "invalid_replay"), manifest, result, events
        )
    if result.get("completed") is not True or not replay.get("completed"):
        return ArtifactValidation(False, "result_trace_outcome_mismatch", manifest, result, events)
    if any(
        event.type is TraceEventType.POLICY_EVENT and event.verdict == "deny" for event in events
    ):
        return ArtifactValidation(False, "terminal_policy_deny", manifest, result, events)
    return ArtifactValidation(True, "validated", manifest, result, events)


def _result_verified(event: TraceEvent, *, legacy: bool) -> bool:
    if event.outcome is not None:
        accepted = _ACCEPTED_RETURN_CODES.get(event.tool or "", {0})
        return (
            event.executed is True
            and event.outcome == "succeeded"
            and event.return_code in accepted
            and event.evidence_predicate_passed is True
            and bool(event.result_digest)
        )
    if not legacy:
        return False
    text = event.text or ""
    if re.search(r"\brc=(126|127|2)\b", text):
        return False
    return bool(
        re.search(r"\brc=0\b", text)
        or "success=True" in text
        or "'open'" in text
        or "'closed'" in text
        or "live_hosts=yes" in text
        or "reachable=yes" in text
        or "assessment_ran=yes" in text
    )


def replay_run(run_dir: str | Path) -> dict:
    root = Path(run_dir)
    manifest_path = root / "manifest.json"
    try:
        raw_lines = [line for line in (root / "trace.jsonl").read_text().splitlines() if line]
        events = [TraceEvent.model_validate_json(line) for line in raw_lines]
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    except (OSError, json.JSONDecodeError, ValidationError, ValueError):
        return _failure("malformed_trace")

    expected_run_id = manifest.get("run_id") or (events[0].run_id if events else "")
    integrity_error = _verify_integrity(events, expected_run_id)
    if integrity_error:
        return _failure(integrity_error, events)
    legacy = not any(item.event_digest for item in events)

    policy_allowed = False
    approval_seen = False
    terminal: str | None = None
    real_calls: dict[str, TraceEvent] = {}
    verified_results: list[TraceEvent] = []
    approval_required = False
    approved_fingerprint: str | None = None

    for event in events:
        if event.type is TraceEventType.POLICY_EVENT:
            if event.verdict == "deny":
                terminal = "policy_denied"
            elif event.verdict == "require_approval":
                approval_required = True
            elif event.verdict == "allow":
                policy_allowed = True
            if event.rule in {"approval_valid", "t3_approval_verified", "t3b_approval_consumed"}:
                approval_seen = True
                policy_allowed = True
        elif event.type is TraceEventType.EXECUTION_STATE:
            if event.state == "approved":
                approval_seen = True
                approved_fingerprint = event.approval_fingerprint
            elif event.state in {"killed", "cancelling", "blocked", "failed"}:
                terminal = event.state
            elif event.state in {"running", "verified"}:
                if terminal is not None:
                    return _failure("execution_after_terminal_state", events)
                if event.state == "verified" and not verified_results:
                    return _failure("completion_without_verified_result", events)
        elif event.type is TraceEventType.TOOL_CALL:
            if event.executed is True:
                key = event.action_id or f"{event.tool}:{event.seq}"
                real_calls[key] = event
            if event.mode is ToolMode.REAL:
                if terminal is not None:
                    return _failure("execution_after_policy_deny", events)
                if not policy_allowed:
                    return _failure("execution_before_policy_allow", events)
                if approval_required and not approval_seen:
                    return _failure("approval_required", events)
                if approval_required and approved_fingerprint != event.approval_fingerprint:
                    return _failure("approval_fingerprint_mismatch", events)
        elif event.type is TraceEventType.TOOL_RESULT:
            if terminal is not None:
                return _failure("result_after_terminal_state", events)
            if event.mode is ToolMode.REAL and not policy_allowed:
                return _failure("result_before_policy_allow", events)
            if event.action_id:
                call = real_calls.get(event.action_id)
                if call is None:
                    return _failure("result_without_executed_call", events)
                if (
                    call.asset_id != event.asset_id
                    or call.profile_id != event.profile_id
                    or call.tool != event.tool
                ):
                    return _failure("result_binding_mismatch", events)
            if _result_verified(event, legacy=legacy):
                verified_results.append(event)

    had_error = any(item.type is TraceEventType.ERROR for item in events)
    if terminal is not None:
        return {
            **_failure(terminal, events),
            "valid": True,
        }
    rules = {item.rule for item in events if item.rule}
    t3_access = "credential_lease_created" in rules or "session_requested" in rules
    completed = bool(verified_results) and not had_error
    result = {
        "completed": completed,
        "valid": True,
        "failure_reason": "" if completed else "no_verified_successful_result",
        "n_events": len(events),
        "had_error": had_error,
        "n_tool_results": sum(item.type is TraceEventType.TOOL_RESULT for item in events),
        "integrity": "legacy" if legacy else "verified_chain",
    }
    if t3_access:
        approval = bool({"t3_approval_verified", "t3b_approval_consumed"} & rules)
        authenticated = "authentication_succeeded" in rules
        closed = "session_closed" in rules
        invalidated = "credential_lease_invalidated" in rules
        cleanup = closed and invalidated and "cleanup_failed" not in rules
        stopped = "kill_switch_activated" in rules
        assessment = completed and approval and authenticated and cleanup and not stopped
        result.update(
            {
                "completed": assessment,
                "assessment_succeeded": assessment,
                "approval_succeeded": approval,
                "authentication_succeeded": authenticated,
                "commands_attempted": len(
                    [
                        item
                        for item in events
                        if item.type is TraceEventType.TOOL_RESULT
                        and item.tool == "t3-fixed-observation"
                    ]
                ),
                "commands_succeeded": len(
                    [item for item in verified_results if item.tool == "t3-fixed-observation"]
                ),
                "stopped_by_kill_switch": stopped,
                "session_closed": closed,
                "cleanup_succeeded": cleanup,
                "credential_lease_invalidated": invalidated,
            }
        )
    return result
