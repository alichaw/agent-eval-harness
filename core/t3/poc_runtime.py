"""Exact protected runtime for the additive T3 PoC execution path."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.t3.poc_registry import ACTIONS, ASSET_ID


class AssetBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target: str
    port: Literal[22]
    credential_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
    username: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
    identity_agent: str
    pinned_host_key: str

    @field_validator("target")
    @classmethod
    def ipv4_only(cls, value: str) -> str:
        return str(ipaddress.IPv4Address(value))

    @field_validator("identity_agent")
    @classmethod
    def absolute_agent(cls, value: str) -> str:
        if not Path(value).is_absolute():
            raise ValueError("absolute identity-agent path required")
        return value

    @field_validator("pinned_host_key")
    @classmethod
    def ed25519_only(cls, value: str) -> str:
        fields = value.split()
        if len(fields) != 2 or fields[0] != "ssh-ed25519":
            raise ValueError("pinned Ed25519 host key required")
        return value


class PocRuntime(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["hexstrike-t3-runtime/v1"]
    runtime_revision: UUID
    assets: dict[str, AssetBinding]
    approval_database: str
    evidence_root: str
    kill_switch_file: str
    action_policy: dict[Literal["enabled_action_ids"], tuple[str, ...]]

    @model_validator(mode="after")
    def exact_contract(self):
        if set(self.assets) != {ASSET_ID}:
            raise ValueError("exact approved asset required")
        enabled = self.action_policy.get("enabled_action_ids", ())
        if tuple(enabled) != tuple(ACTIONS):
            raise ValueError("registered enabled actions required")
        for value in (self.approval_database, self.evidence_root, self.kill_switch_file):
            if not Path(value).is_absolute():
                raise ValueError("absolute protected paths required")
        return self

    @property
    def digest(self) -> str:
        raw = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def target_network(self) -> str:
        target = self.assets[ASSET_ID].target
        return str(ipaddress.ip_network(f"{target}/32", strict=True))


def _safe_regular_file(path: Path, *, owner_uid: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("protected runtime metadata invalid")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_runtime(path: str | Path, *, owner_uid: int | None = None) -> PocRuntime:
    selected = Path(path)
    if selected.is_symlink():
        raise ValueError("protected runtime unavailable")
    uid = os.geteuid() if owner_uid is None else owner_uid
    try:
        raw = _safe_regular_file(selected, owner_uid=uid)
        return PocRuntime.model_validate_json(raw)
    except (OSError, ValueError) as exc:
        raise ValueError("protected runtime invalid") from exc
