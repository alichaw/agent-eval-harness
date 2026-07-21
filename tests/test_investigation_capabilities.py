import pytest

from core.investigation.capabilities import (
    DEFAULT_CAPABILITY_PROFILES,
    CapabilityMappingError,
    CapabilityProfileMap,
)
from core.profiles import ProfileCatalog


def test_default_mapping_resolves_every_profile(tmp_path):
    profiles = "profiles:\n" + "".join(
        f"  {profile}:\n"
        "    description: test\n"
        "    interaction_mode: active\n"
        "    risk_tier: low\n"
        "    tool_id: test\n"
        for profile in DEFAULT_CAPABILITY_PROFILES.values()
    )
    path = tmp_path / "profiles.yaml"
    path.write_text(profiles)
    mapping = CapabilityProfileMap.from_catalog(ProfileCatalog.from_yaml(path))
    for capability, profile in DEFAULT_CAPABILITY_PROFILES.items():
        assert mapping.resolve(capability) == profile


def test_missing_mapping_fails_closed(tmp_path):
    path = tmp_path / "profiles.yaml"
    path.write_text("profiles: {}\n")
    with pytest.raises(CapabilityMappingError):
        CapabilityProfileMap.from_catalog(ProfileCatalog.from_yaml(path), {})
