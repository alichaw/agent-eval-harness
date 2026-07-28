"""Validated capability-to-profile bindings for evidence-driven investigations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from core.investigation.router import (
    AD_CAPABILITIES,
    SERVICE_INVENTORY,
    SMB_CAPABILITIES,
    WEB_CAPABILITIES,
)
from core.profiles import ProfileCatalog

ROUTABLE_CAPABILITIES = frozenset(
    {
        SERVICE_INVENTORY,
        *WEB_CAPABILITIES,
        *SMB_CAPABILITIES,
        *AD_CAPABILITIES,
    }
)

DEFAULT_CAPABILITY_PROFILES: Mapping[str, str] = MappingProxyType(
    {
        SERVICE_INVENTORY: "tcp-service-inventory-low",
        "web.http.metadata": "http-fingerprint-low",
        "web.content.discovery": "web-directory-enum-low",
        "web.vulnerability.template_assess": "web-vulnerability-scan-bounded",
        "windows.smb.posture_assess": "smb-posture-assessment",
        "windows.smb.anonymous_access_assess": "smb-anonymous-access-check",
        "windows.smb.known_vulnerability_assess": "smb-ms17-010-check",
        "windows.ad.smb_share_enum": "smb-share-enum-low",
        "windows.ad.smb_rid_user_enum": "smb-user-enum-rid-low",
        "windows.ad.null_session_posture": "ad-null-session-posture",
    }
)


class CapabilityMappingError(ValueError):
    """Invalid capability mapping; callers must fail closed."""


@dataclass(frozen=True)
class CapabilityProfileMap:
    """Complete one-to-one bindings from routed capabilities to fixed profiles."""

    _mapping: Mapping[str, str]

    @classmethod
    def from_catalog(
        cls,
        catalog: ProfileCatalog,
        mapping: Mapping[str, str] = DEFAULT_CAPABILITY_PROFILES,
    ) -> CapabilityProfileMap:
        values = list(mapping.values())
        problems: list[str] = []
        missing = ROUTABLE_CAPABILITIES - set(mapping)
        unknown = set(mapping) - ROUTABLE_CAPABILITIES
        duplicates = {item for item in values if values.count(item) > 1}
        absent = {item for item in values if item not in catalog}
        if missing:
            problems.append(f"missing capabilities: {sorted(missing)}")
        if unknown:
            problems.append(f"unknown capabilities: {sorted(unknown)}")
        if duplicates:
            problems.append(f"duplicate profiles: {sorted(duplicates)}")
        if absent:
            problems.append(f"profiles absent from catalog: {sorted(absent)}")
        if problems:
            raise CapabilityMappingError("; ".join(problems))
        return cls(MappingProxyType(dict(mapping)))

    @property
    def capabilities(self) -> set[str]:
        return set(self._mapping)

    def resolve(self, capability_id: str) -> str:
        try:
            return self._mapping[capability_id]
        except KeyError as exc:
            raise CapabilityMappingError(f"unmapped capability '{capability_id}'") from exc
