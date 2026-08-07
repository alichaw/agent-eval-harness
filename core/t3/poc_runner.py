"""Harness-side unified T3 requester; never reads or consumes approval state."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from core.t3.poc_approval import authorization_digest
from core.t3.poc_registry import action
from core.t3.poc_runtime import PocRuntime

ENDPOINT = "http://127.0.0.1:8888/api/v1/t3/executions"


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    authorization_id: str
    canonical_action: str


class AuthorizationFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    authorization_id: str


def load_authorization(path: str | Path, *, owner_uid: int | None = None) -> str:
    selected = Path(path)
    if selected.is_symlink():
        raise ValueError("protected authorization invalid")
    descriptor = -1
    try:
        descriptor = os.open(selected, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        uid = os.geteuid() if owner_uid is None else owner_uid
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("protected authorization invalid")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            value = AuthorizationFile.model_validate(json.load(handle))
        return value.authorization_id
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("protected authorization invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["hexstrike-t3-result/v1"]
    authorization_id_digest: str
    action_id: str
    status: Literal["completed", "failed"]
    runtime_digest: str
    executor_family: Literal["WINDOWS_SSH"]
    tool_calls: int
    evidence_ref: str
    evidence_digest: str


def run(
    runtime: PocRuntime,
    *,
    authorization_id: str,
    action_id: str,
    session: Any,
) -> dict[str, Any]:
    selected = action(action_id)
    if action_id not in runtime.action_policy["enabled_action_ids"]:
        raise ValueError("action_not_enabled")
    request = ExecutionRequest(
        authorization_id=authorization_id,
        canonical_action=selected.action_id,
    )
    response = session.post(ENDPOINT, json=request.model_dump(), timeout=70)
    value = response.json()
    try:
        response.raise_for_status()
    except Exception:
        allowed = {
            "authorization_invalid",
            "authorization_rejected",
            "unknown_action",
            "action_not_enabled",
            "kill_switch_engaged",
            "kill_switch_state_invalid",
            "prerequisite_not_satisfied",
            "request_schema_invalid",
        }
        code = value.get("error") if isinstance(value, dict) else None
        raise ValueError(code if code in allowed else "execution_denied") from None
    try:
        result = ExecutionResult.model_validate(value)
    except Exception as exc:
        raise ValueError("result_invalid") from exc
    expected_digest = authorization_digest(authorization_id)
    if (
        result.authorization_id_digest != expected_digest
        or result.action_id != selected.action_id
        or result.runtime_digest != runtime.digest
        or result.tool_calls < 0
        or result.tool_calls > selected.maximum_tool_calls
        or not result.evidence_ref
    ):
        raise ValueError("result_invalid")
    return result.model_dump()
