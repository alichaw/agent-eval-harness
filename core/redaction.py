"""Deterministic per-run pseudonymisation for artifacts and LLM feedback."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
from collections.abc import Mapping
from typing import Any

_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


class Redactor:
    """Replace known targets with asset IDs and unknown IPv4 values with pseudonyms."""

    def __init__(self, target_aliases: Mapping[str, str] | None = None, salt: bytes | None = None):
        self.target_aliases = {
            str(target): str(alias)
            for target, alias in (target_aliases or {}).items()
            if str(target)
        }
        self._salt = secrets.token_bytes(32) if salt is None else salt
        self._ip_aliases: dict[str, str] = {}

    @classmethod
    def from_assets(cls, assets) -> Redactor:
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
        return cls(aliases)

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

    def text(self, value: str) -> str:
        result = value
        for target, alias in sorted(self.target_aliases.items(), key=lambda item: -len(item[0])):
            result = result.replace(target, alias)
        return _IPV4_RE.sub(self._redact_ipv4, result)

    def value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {key: self.value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.value(item) for item in value)
        return value
