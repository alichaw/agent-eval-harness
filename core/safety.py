"""Fail-closed approval tokens, execution states, and kill switches."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path


class ExecutionState(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    RUNNING = "running"
    VERIFIED = "verified"
    BLOCKED = "blocked"
    FAILED = "failed"
    EXHAUSTED = "exhausted"
    KILLED = "killed"


class ApprovalError(ValueError):
    pass


@dataclass(frozen=True)
class ApprovalClaims:
    asset_id: str
    profile_id: str
    profile_hash: str
    expires_at: int
    nonce: str


def profile_fingerprint(profile) -> str:
    limits = asdict(profile.limits)
    document = {
        "profile_id": profile.profile_id,
        "tool_id": profile.tool_id,
        "parameters": profile.parameters,
        "limits": limits,
        "risk_tier": profile.risk_tier.value,
        "interaction_mode": profile.interaction_mode.value,
        "approval_required": profile.approval_required,
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


class ApprovalAuthority:
    """Issue and atomically consume HMAC-signed, single-use approvals."""

    def __init__(self, secret: bytes, spent_dir: str | Path):
        if len(secret) < 32:
            raise ApprovalError("approval secret must contain at least 32 bytes")
        self.secret = secret
        self.spent_dir = Path(spent_dir)

    @staticmethod
    def _encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    @classmethod
    def _decode(cls, value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(value + padding)
        if cls._encode(raw) != value:
            raise ApprovalError("non-canonical approval token encoding")
        return raw

    def issue(
        self,
        asset_id: str,
        profile_id: str,
        profile_hash: str,
        ttl_seconds: int = 300,
    ) -> str:
        if not 1 <= ttl_seconds <= 3600:
            raise ApprovalError("approval TTL must be between 1 and 3600 seconds")
        claims = ApprovalClaims(
            asset_id=asset_id,
            profile_id=profile_id,
            profile_hash=profile_hash,
            expires_at=int(time.time()) + ttl_seconds,
            nonce=secrets.token_urlsafe(24),
        )
        payload = json.dumps(asdict(claims), sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self.secret, payload, hashlib.sha256).digest()
        return f"{self._encode(payload)}.{self._encode(signature)}"

    def verify_and_consume(
        self,
        token: str,
        asset_id: str,
        profile_id: str,
        profile_hash: str,
    ) -> ApprovalClaims:
        try:
            payload_part, signature_part = token.split(".", 1)
            payload = self._decode(payload_part)
            supplied_signature = self._decode(signature_part)
        except Exception as exc:
            raise ApprovalError("malformed approval token") from exc

        expected_signature = hmac.new(self.secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ApprovalError("invalid approval signature")

        try:
            claims = ApprovalClaims(**json.loads(payload))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ApprovalError("invalid approval claims") from exc

        if int(time.time()) >= claims.expires_at:
            raise ApprovalError("approval expired")
        if claims.asset_id != asset_id or claims.profile_id != profile_id:
            raise ApprovalError("approval does not match asset/profile")
        if claims.profile_hash != profile_hash:
            raise ApprovalError("approval profile hash mismatch")

        self.spent_dir.mkdir(parents=True, exist_ok=True)
        marker = self.spent_dir / hashlib.sha256(claims.nonce.encode()).hexdigest()
        try:
            fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ApprovalError("approval already consumed") from exc
        else:
            os.close(fd)
        return claims


@dataclass(frozen=True)
class KillSwitch:
    path: Path

    def engaged(self) -> bool:
        return self.path.exists()
