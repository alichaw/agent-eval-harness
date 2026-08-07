import ipaddress
import re
import subprocess
from pathlib import Path

import yaml

DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?![0-9.])")


def _tracked_files() -> list[Path]:
    names = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    return [Path(value.decode()) for value in names if value]


def test_tracked_asset_targets_use_documentation_ipv4_only():
    assets = yaml.safe_load(Path("assets.yaml").read_text(encoding="utf-8"))["assets"]
    for asset in assets.values():
        target = asset.get("target")
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            continue
        assert address.version == 4
        assert any(address in network for network in DOCUMENTATION_NETWORKS)


def test_tracked_target_configuration_has_no_public_ipv4_literal():
    candidates = [
        path
        for path in _tracked_files()
        if path.suffix in {".yaml", ".yml", ".json"}
        and (len(path.parts) == 1 or path.parts[0] == "config")
    ]
    violations = []
    for path in candidates:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for matched in IPV4.finditer(text):
            try:
                network = ipaddress.ip_network(matched.group(), strict=False)
            except ValueError:
                continue
            address = network.network_address
            if address.is_global and not any(address in item for item in DOCUMENTATION_NETWORKS):
                violations.append(f"{path}:non_documentation_public_ipv4")
    assert violations == []
