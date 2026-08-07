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
    CANCELLING = "cancelling"
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
    not_before: int
    expires_at: int
    nonce: str
    credential_id: str = ""
    action_fingerprint: str = ""


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
        "allowed_asset_types": profile.allowed_asset_types,
        "internet_egress": profile.internet_egress,
        "evidence_required": profile.evidence_required,
        "forbidden_fields": profile.forbidden_fields,
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
        delay_seconds: int = 0,
        credential_id: str = "",
        action_fingerprint: str = "",
    ) -> str:
        if not 1 <= ttl_seconds <= 3600:
            raise ApprovalError("approval TTL must be between 1 and 3600 seconds")
        # Cooling-off window: the approval exists from the moment it's issued (so it's
        # already logged/auditable) but cannot be CONSUMED until not_before. This is a
        # single-operator substitute for two-person review — it forces a mandatory gap
        # between "I decided to do this" and "this can actually run", so an approval
        # can't be minted and used in the same breath under in-the-moment pressure.
        if not 0 <= delay_seconds <= 86_400:
            raise ApprovalError("approval delay must be between 0 and 86400 seconds")
        not_before = int(time.time()) + delay_seconds
        claims = ApprovalClaims(
            asset_id=asset_id,
            profile_id=profile_id,
            profile_hash=profile_hash,
            not_before=not_before,
            expires_at=not_before + ttl_seconds,
            nonce=secrets.token_urlsafe(24),
            # Binds the approval to exactly one named credential (core/credentials.py)
            # -- an approval minted for "creds-vm-lab-01-admin" cannot be replayed
            # against a run that loads a different credential, even for the same
            # asset/profile. Empty string (default) means no credential is bound,
            # which is every T1/T2 approval today -- fully backward compatible.
            credential_id=credential_id,
            # T3 approvals are bound to the complete, canonical control request.
            # Empty keeps all existing T1/T2 approval behavior unchanged.
            action_fingerprint=action_fingerprint,
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
        credential_id: str = "",
        action_fingerprint: str = "",
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

        now = int(time.time())
        if now < claims.not_before:
            raise ApprovalError(
                f"approval not active yet — usable in {claims.not_before - now}s "
                f"(cooling-off period, not_before={claims.not_before})"
            )
        if now >= claims.expires_at:
            raise ApprovalError("approval expired")
        if claims.asset_id != asset_id or claims.profile_id != profile_id:
            raise ApprovalError("approval does not match asset/profile")
        if claims.profile_hash != profile_hash:
            raise ApprovalError("approval profile hash mismatch")
        if claims.credential_id != credential_id:
            raise ApprovalError("approval does not match credential")
        if claims.action_fingerprint != action_fingerprint:
            raise ApprovalError("approval action fingerprint mismatch")

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
