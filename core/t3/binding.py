"""Canonical, secret-free binding for T3-A/T3-B operator runtime state."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


def canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RuntimeBinding:
    asset_id: str
    target_identity: str
    host: str
    port: int
    credential_ref: str
    principal: str
    host_key_algorithm: str
    host_key_fingerprint: str
    transport_type: str
    runtime_config_digest: str
    asset_registry_digest: str
    policy_digest: str
    profile_digest: str
    prerequisite_stage: str
    prerequisite_capability: str
    session_limits_digest: str
    action_registry_digest: str

    @property
    def fingerprint(self) -> str:
        return canonical_digest(asdict(self))


def host_key_identity(pinned_host_key: str) -> tuple[str, str]:
    algorithm, encoded = pinned_host_key.split(" ", 1)
    return algorithm, hashlib.sha256(encoded.encode()).hexdigest()
