"""Deterministic per-run pseudonymisation for artifacts and LLM feedback.

T3-specific redaction patterns for credentials, hashes, and tickets that must
NEVER appear in trace/runs output.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
from collections.abc import Mapping
from typing import Any

_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

# T3-specific credential patterns (to be redacted unconditionally)
_NTLM_HASH_RE = re.compile(
    r"\b[a-f0-9]{32}:[a-f0-9]{32}\b", re.IGNORECASE
)  # NTLM: aabbccdd:eeffgghh
_KERBEROS_TICKET_RE = re.compile(r"\b[A-Z0-9+/]{100,}\b")  # TGT/TGS (rough heuristic)
_PASSWORD_PATTERN_RE = re.compile(
    r"(?:password|passwd|pwd|secret)\s*[=:]\s*[^\s]{1,128}", re.IGNORECASE
)
_LM_HASH_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)  # LM hash (32 hex chars)
_PLAINTEXT_PASSWORD_RE = re.compile(
    r"(?:login|user|admin|root|account)(?:\s+)?[=:@/](?:\s+)?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\",.<>/?\\|`~]{8,128})",
    re.IGNORECASE,
)


class Redactor:
    """Replace known targets with asset IDs, unknown IPv4s with pseudonyms, and T3 credentials."""

    def __init__(
        self,
        target_aliases: Mapping[str, str] | None = None,
        salt: bytes | None = None,
        redact_credentials: bool = False,
    ):
        self.target_aliases = {
            str(target): str(alias)
            for target, alias in (target_aliases or {}).items()
            if str(target)
        }
        self._salt = secrets.token_bytes(32) if salt is None else salt
        self._ip_aliases: dict[str, str] = {}
        self.redact_credentials = redact_credentials  # T3-High output redaction

    @classmethod
    def from_assets(cls, assets, redact_credentials: bool = False) -> Redactor:
        aliases: dict[str, str] = {}
        if assets is not None:
            for asset_id, asset in assets.items():
                target = str(asset.get("target", ""))
                if target:
                    # Keep redacted targets visibly non-routable.  A bare asset ID
                    # inside a URL (for example ``http://asset:web:8000``) looks
                    # like a malformed execution target instead of an artifact
                    # pseudonym.
                    aliases[target] = f"<{asset_id}>"
        return cls(aliases, redact_credentials=redact_credentials)

    def _ip_alias(self, value: str) -> str:
        if value not in self._ip_aliases:
            digest = hashlib.sha256(self._salt + value.encode()).hexdigest()[:8]
            self._ip_aliases[value] = f"ip:{digest}"
        return self._ip_aliases[value]

    def _redact_ipv4(self, match: re.Match[str]) -> str:
        value = match.group(0)
        try:
            ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            return value
        return self._ip_alias(value)

    def _redact_credential(self, match: re.Match[str]) -> str:
        """Redact matched credential to <redacted:credential>."""
        return "<redacted:credential>"

    def text(self, value: str) -> str:
        result = value
        for target, alias in sorted(self.target_aliases.items(), key=lambda item: -len(item[0])):
            result = result.replace(target, alias)

        # Always redact IPv4 addresses
        result = _IPV4_RE.sub(self._redact_ipv4, result)

        # T3-specific credential redaction (if enabled, always applied to T3-High output)
        if self.redact_credentials:
            # Redact NTLM hashes (aabbccdd:eeffgghh format)
            result = _NTLM_HASH_RE.sub(self._redact_credential, result)
            # Redact potential Kerberos tickets (base64-like long strings)
            result = _KERBEROS_TICKET_RE.sub(self._redact_credential, result)
            # Redact explicit password assignments
            result = _PASSWORD_PATTERN_RE.sub(self._redact_credential, result)
            # Redact LM hashes
            result = _LM_HASH_RE.sub(self._redact_credential, result)

        return result

    def value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if self.redact_credentials and key.lower() in {
                    "password",
                    "passwd",
                    "pwd",
                    "secret",
                    "hash",
                    "ticket",
                    "credential",
                    "credential_id",
                }:
                    result[key] = "<redacted:credential>"
                else:
                    result[key] = self.value(item)
            return result
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.value(item) for item in value)
        return value
