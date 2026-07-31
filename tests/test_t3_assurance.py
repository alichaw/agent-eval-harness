import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from core.schemas.models import TaskSpec
from core.t3.access import T3AuthorizedAccessProposal
from core.t3.assurance import (
    COMMON_CHECKS,
    DEFERRED_CHECKS,
    AssuranceContext,
    AssuranceProfile,
    ReadinessStatus,
    evaluate_readiness,
    loopback_listener_ready,
)
from core.t3.runtime import _read_private_config


def runtime_config(tmp_path, profile=None):
    value = {
        "asset_id": "asset:test",
        "profile_id": "t3-authorized-access-bounded",
        "credential_ref": "credential:test",
        "username": "synthetic",
        "private_key_path": "/synthetic/not-read",
        "pinned_host_key": "ssh-ed25519 " + "A" * 68,
    }
    if profile is not None:
        value["assurance"] = {"profile": profile}
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def passing_common():
    return dict.fromkeys(COMMON_CHECKS, True)


def passing_hardened():
    return dict.fromkeys(DEFERRED_CHECKS, True)


@pytest.mark.parametrize("profile", ["poc", "hardened"])
def test_trusted_assurance_profiles_load_and_remain_immutable(tmp_path, profile):
    config = _read_private_config(runtime_config(tmp_path, profile))
    assert config.assurance.profile.value == profile
    with pytest.raises(ValidationError):
        config.assurance.profile = AssuranceProfile.POC


def test_missing_profile_defaults_hardened_and_unknown_is_rejected(tmp_path):
    assert (
        _read_private_config(runtime_config(tmp_path)).assurance.profile
        is AssuranceProfile.HARDENED
    )
    with pytest.raises(ValueError, match="operator runtime configuration invalid"):
        _read_private_config(runtime_config(tmp_path, "unknown"))


def test_operator_runtime_rejects_non_loopback_hexstrike_endpoint(tmp_path):
    path = runtime_config(tmp_path, "poc")
    value = json.loads(path.read_text())
    value["hexstrike_url"] = "http://0.0.0.0:8888"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    with pytest.raises(ValueError, match="operator runtime configuration invalid"):
        _read_private_config(path)


def test_agent_task_and_request_cannot_select_assurance_profile():
    with pytest.raises(ValidationError):
        T3AuthorizedAccessProposal.model_validate(
            {
                "asset_id": "asset:test",
                "profile_id": "t3-authorized-access-bounded",
                "assurance_profile": "poc",
            }
        )
    task = yaml.safe_load(
        Path("tests/fixtures/cases/valid_recon_basic.yaml").read_text(encoding="utf-8")
    )
    task["assurance_profile"] = "poc"
    with pytest.raises(ValidationError, match="assurance_profile"):
        TaskSpec.model_validate(task)


def test_context_is_frozen_and_not_affected_by_later_configuration_changes():
    context = AssuranceContext(AssuranceProfile.HARDENED)
    with pytest.raises(FrozenInstanceError):
        context.profile = AssuranceProfile.POC
    assert context.profile is AssuranceProfile.HARDENED


def test_poc_readiness_skips_only_deferred_controls():
    report = evaluate_readiness(
        AssuranceContext(AssuranceProfile.POC),
        common=passing_common(),
        hardened={},
    )
    assert report.ready
    assert report.ready_with_profile_skips
    skipped = [item for item in report.checks if item.status is ReadinessStatus.SKIPPED_BY_PROFILE]
    passed = [item for item in report.checks if item.status is ReadinessStatus.PASS]
    assert {item.check for item in skipped} == set(DEFERRED_CHECKS)
    assert {item.check for item in passed} == set(COMMON_CHECKS)
    assert not ({item.check for item in skipped} & {item.check for item in passed})


@pytest.mark.parametrize("check", list(COMMON_CHECKS))
def test_poc_fails_when_any_common_control_is_missing(check):
    common = passing_common()
    common[check] = False
    report = evaluate_readiness(
        AssuranceContext(AssuranceProfile.POC),
        common=common,
        hardened={},
    )
    assert not report.ready
    assert next(item for item in report.checks if item.check == check).status is (
        ReadinessStatus.FAIL
    )


@pytest.mark.parametrize("check", list(DEFERRED_CHECKS))
def test_hardened_fails_closed_for_every_missing_hardened_control(check):
    hardened = passing_hardened()
    hardened[check] = False
    report = evaluate_readiness(
        AssuranceContext(AssuranceProfile.HARDENED),
        common=passing_common(),
        hardened=hardened,
    )
    assert not report.ready
    assert next(item for item in report.checks if item.check == check).status is (
        ReadinessStatus.FAIL
    )
    assert all(item.status is not ReadinessStatus.SKIPPED_BY_PROFILE for item in report.checks)


def test_unexpected_readiness_error_fails_instead_of_skipping():
    class Broken(dict):
        def get(self, key, default=None):
            raise RuntimeError("synthetic")

    report = evaluate_readiness(
        AssuranceContext(AssuranceProfile.POC),
        common=Broken(),
        hardened={},
    )
    assert not report.ready
    assert all(
        item.status is ReadinessStatus.FAIL for item in report.checks if item.check in COMMON_CHECKS
    )


@pytest.mark.parametrize("profile", [AssuranceProfile.POC, AssuranceProfile.HARDENED])
def test_unsafe_hexstrike_exposure_fails_both_profiles(profile):
    common = passing_common()
    common["hexstrike_loopback_endpoint"] = False
    report = evaluate_readiness(
        AssuranceContext(profile),
        common=common,
        hardened=passing_hardened(),
    )
    assert not report.ready
    endpoint = next(item for item in report.checks if item.check == "hexstrike_loopback_endpoint")
    assert endpoint.status is ReadinessStatus.FAIL


def test_listener_check_rejects_wildcard_and_accepts_loopback(tmp_path):
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp6.write_text("header\n")
    tcp.write_text("header\n 0: 00000000:22B8 00000000:0000 0A ignored\n")
    tables = (
        (tcp, "0100007F"),
        (tcp6, "00000000000000000000000001000000"),
    )
    assert not loopback_listener_ready(tables=tables)
    tcp.write_text("header\n 0: 0100007F:22B8 00000000:0000 0A ignored\n")
    assert loopback_listener_ready(tables=tables)
