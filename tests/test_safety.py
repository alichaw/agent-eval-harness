"""Safety-control tests for approval binding, replay resistance, and kill switch."""

import time

import pytest

from core.profiles import ProfileCatalog
from core.safety import ApprovalAuthority, ApprovalError, KillSwitch, profile_fingerprint


def _profile(tmp_path):
    path = tmp_path / "profiles.yaml"
    path.write_text(
        """
profiles:
  approved-scan:
    interaction_mode: active
    risk_tier: medium
    allowed_asset_types: [host]
    tool_id: nmap
    parameters: {scan_type: "-sV"}
    approval_required: true
"""
    )
    return ProfileCatalog.from_yaml(path).get("approved-scan")


def test_approval_is_bound_to_asset_profile_and_hash(tmp_path):
    profile = _profile(tmp_path)
    fingerprint = profile_fingerprint(profile)
    authority = ApprovalAuthority(b"x" * 32, tmp_path / "spent")
    token = authority.issue("asset:test", profile.profile_id, fingerprint)

    claims = authority.verify_and_consume(
        token,
        "asset:test",
        profile.profile_id,
        fingerprint,
    )

    assert claims.asset_id == "asset:test"


def test_approval_cannot_be_replayed(tmp_path):
    profile = _profile(tmp_path)
    fingerprint = profile_fingerprint(profile)
    authority = ApprovalAuthority(b"x" * 32, tmp_path / "spent")
    token = authority.issue("asset:test", profile.profile_id, fingerprint)
    authority.verify_and_consume(token, "asset:test", profile.profile_id, fingerprint)

    with pytest.raises(ApprovalError, match="already consumed"):
        authority.verify_and_consume(token, "asset:test", profile.profile_id, fingerprint)


def test_approval_rejects_wrong_asset_and_tampering(tmp_path):
    profile = _profile(tmp_path)
    fingerprint = profile_fingerprint(profile)
    authority = ApprovalAuthority(b"x" * 32, tmp_path / "spent")
    token = authority.issue("asset:test", profile.profile_id, fingerprint)

    with pytest.raises(ApprovalError, match="does not match"):
        authority.verify_and_consume(token, "asset:other", profile.profile_id, fingerprint)

    with pytest.raises(ApprovalError, match="signature"):
        authority.verify_and_consume(token[:-1] + "A", "asset:test", profile.profile_id, fingerprint)


def test_expired_approval_is_rejected(tmp_path, monkeypatch):
    profile = _profile(tmp_path)
    fingerprint = profile_fingerprint(profile)
    authority = ApprovalAuthority(b"x" * 32, tmp_path / "spent")
    token = authority.issue("asset:test", profile.profile_id, fingerprint, ttl_seconds=1)
    monkeypatch.setattr(time, "time", lambda: 2_000_000_000)

    with pytest.raises(ApprovalError, match="expired"):
        authority.verify_and_consume(token, "asset:test", profile.profile_id, fingerprint)


def test_kill_switch_is_file_backed(tmp_path):
    switch = KillSwitch(tmp_path / "STOP")
    assert switch.engaged() is False
    switch.path.touch()
    assert switch.engaged() is True
