"""Trusted, immutable assurance profiles and structured readiness results."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict


class AssuranceProfile(str, Enum):
    POC = "poc"
    HARDENED = "hardened"


class AssuranceConfig(BaseModel):
    """Operator-owned assurance selection embedded in the protected runtime file."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    profile: AssuranceProfile = AssuranceProfile.HARDENED


class ReadinessStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED_BY_PROFILE = "SKIPPED_BY_PROFILE"


@dataclass(frozen=True)
class AssuranceRequirements:
    require_signed_execution_permit: bool
    require_approval_signing_key_isolation: bool
    require_downstream_delegation_token: bool
    require_dedicated_executor_identity: bool
    require_hardened_systemd: bool
    require_uid_network_enforcement: bool


_REQUIREMENTS = MappingProxyType(
    {
        AssuranceProfile.POC: AssuranceRequirements(
            False,
            False,
            False,
            False,
            False,
            False,
        ),
        AssuranceProfile.HARDENED: AssuranceRequirements(
            True,
            True,
            True,
            True,
            True,
            True,
        ),
    }
)


@dataclass(frozen=True)
class AssuranceContext:
    profile: AssuranceProfile
    trusted_source: str = "operator_runtime_config"

    @property
    def requirements(self) -> AssuranceRequirements:
        return _REQUIREMENTS[self.profile]


@dataclass(frozen=True)
class ReadinessCheck:
    check: str
    status: ReadinessStatus
    profile: AssuranceProfile
    reason: str
    timestamp: str
    aisvs_reference: str = ""
    safe_detail: str = ""


@dataclass(frozen=True)
class ReadinessReport:
    profile: AssuranceProfile
    trusted_source: str
    checks: tuple[ReadinessCheck, ...]

    @property
    def ready(self) -> bool:
        return all(item.status is not ReadinessStatus.FAIL for item in self.checks)

    @property
    def ready_with_profile_skips(self) -> bool:
        return self.ready and any(
            item.status is ReadinessStatus.SKIPPED_BY_PROFILE for item in self.checks
        )


COMMON_CHECKS: Mapping[str, str] = MappingProxyType(
    {
        "asset_allowlist_and_deny_precedence": "9.5.1",
        "t3_profile_registration": "9.5.1",
        "hexstrike_loopback_endpoint": "9.5.1",
        "human_approval": "9.2.1",
        "single_use_approval_and_replay": "9.2.1",
        "credential_reference_isolation": "9.5.1",
        "kill_switch": "9.5.1",
        "audit_trace_and_evidence": "",
        "execution_limits": "9.5.1",
    }
)

DEFERRED_CHECKS: Mapping[str, tuple[str, str]] = MappingProxyType(
    {
        "signed_execution_permit": ("require_signed_execution_permit", "9.2.8"),
        "approval_signing_key_isolation": (
            "require_approval_signing_key_isolation",
            "9.2.9",
        ),
        "downstream_delegation_token": (
            "require_downstream_delegation_token",
            "9.5.2",
        ),
        "dedicated_executor_identity": ("require_dedicated_executor_identity", ""),
        "hardened_systemd_deployment": ("require_hardened_systemd", ""),
        "uid_network_enforcement": ("require_uid_network_enforcement", ""),
    }
)


def loopback_listener_ready(
    port: int = 8888,
    *,
    tables: tuple[tuple[Path, str], ...] | None = None,
) -> bool:
    """Read the kernel listener table without opening a socket or sending traffic."""

    expected_port = f"{port:04X}"
    found = False
    selected_tables = tables or (
        (Path("/proc/net/tcp"), "0100007F"),
        (Path("/proc/net/tcp6"), "00000000000000000000000001000000"),
    )
    for path, loopback in selected_tables:
        try:
            lines = path.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            return False
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            address, selected_port = fields[1].split(":", 1)
            if selected_port != expected_port:
                continue
            found = True
            if address != loopback:
                return False
    return found


def evaluate_readiness(
    context: AssuranceContext,
    *,
    common: Mapping[str, bool],
    hardened: Mapping[str, bool],
    now: datetime | None = None,
) -> ReadinessReport:
    """Evaluate every known check; exceptions and missing inputs fail closed."""

    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    checks: list[ReadinessCheck] = []

    def verified(values: Mapping[str, bool], key: str) -> bool:
        try:
            return values.get(key) is True
        except Exception:  # noqa: BLE001 - readiness errors must fail, never skip
            return False

    for check, reference in COMMON_CHECKS.items():
        passed = verified(common, check)
        checks.append(
            ReadinessCheck(
                check,
                ReadinessStatus.PASS if passed else ReadinessStatus.FAIL,
                context.profile,
                "mandatory control verified" if passed else "mandatory control not verified",
                timestamp,
                reference,
            )
        )
    requirements = context.requirements
    for check, (attribute, reference) in DEFERRED_CHECKS.items():
        required = getattr(requirements, attribute)
        if not required:
            checks.append(
                ReadinessCheck(
                    check,
                    ReadinessStatus.SKIPPED_BY_PROFILE,
                    context.profile,
                    "deferred from the research PoC acceptance scope",
                    timestamp,
                    reference,
                )
            )
            continue
        passed = verified(hardened, check)
        checks.append(
            ReadinessCheck(
                check,
                ReadinessStatus.PASS if passed else ReadinessStatus.FAIL,
                context.profile,
                "hardened control verified" if passed else "required hardened control not verified",
                timestamp,
                reference,
            )
        )
    return ReadinessReport(context.profile, context.trusted_source, tuple(checks))
