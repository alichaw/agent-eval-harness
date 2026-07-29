"""Strict, non-executable control models for T3 action proposals."""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class T3Stage(str, Enum):
    INITIAL_ACCESS = "initial_access"
    WINDOWS_ENUMERATION = "windows_enumeration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_METHOD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SCOPE_IDENTIFIER = _IDENTIFIER


class T3ActionRequest(BaseModel):
    """A bounded action description; it deliberately cannot carry executable input."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    stage: T3Stage
    source_asset_id: str
    destination_asset_id: str | None = None
    capability_id: str
    method: str
    finding_refs: list[str] = Field(default_factory=list, max_length=50)
    evidence_refs: list[str] = Field(min_length=1, max_length=50)
    credential_ref: str | None = None
    command_scope: list[str] = Field(min_length=1, max_length=20)
    written_justification: str = Field(min_length=1, max_length=2000)

    @field_validator(
        "action_id",
        "source_asset_id",
        "destination_asset_id",
        "capability_id",
        "credential_ref",
    )
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is not None and not _IDENTIFIER.fullmatch(value):
            raise ValueError("identifier must use the bounded identifier format")
        return value

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        if not _METHOD.fullmatch(value):
            raise ValueError("method must use the bounded method format")
        return value

    @field_validator("finding_refs", "evidence_refs")
    @classmethod
    def validate_references(cls, values: list[str]) -> list[str]:
        if any(not _IDENTIFIER.fullmatch(value) for value in values):
            raise ValueError("references must use the bounded identifier format")
        if len(set(values)) != len(values):
            raise ValueError("references must be unique")
        return values

    @field_validator("command_scope")
    @classmethod
    def validate_command_scope(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("command_scope entries must be unique")
        if any(not _SCOPE_IDENTIFIER.fullmatch(value) for value in values):
            raise ValueError(
                "command_scope entries must be bounded identifiers without shell constructs"
            )
        return values

    @field_validator("written_justification")
    @classmethod
    def validate_justification(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("written_justification must be non-empty")
        return value

    @model_validator(mode="after")
    def validate_stage_requirements(self) -> T3ActionRequest:
        if self.stage in {T3Stage.INITIAL_ACCESS, T3Stage.PRIVILEGE_ESCALATION}:
            if self.destination_asset_id is not None:
                raise ValueError(f"{self.stage.value} does not accept destination_asset_id")
        elif self.stage is T3Stage.LATERAL_MOVEMENT:
            if self.destination_asset_id is None:
                raise ValueError("lateral_movement requires destination_asset_id")
            if self.destination_asset_id == self.source_asset_id:
                raise ValueError("lateral_movement destination must differ from source")
            if self.credential_ref is None:
                raise ValueError("lateral_movement requires credential_ref")
        return self


def t3_action_fingerprint(request: T3ActionRequest) -> str:
    """Hash canonical JSON, normalizing reference lists that have set semantics."""

    document = request.model_dump(mode="json")
    document["finding_refs"] = sorted(set(document["finding_refs"]))
    document["evidence_refs"] = sorted(set(document["evidence_refs"]))
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()
