from pathlib import Path


def test_permission_setup_script_preserves_non_root_protected_model():
    script = Path("scripts/setup_t3_poc_config_permissions.sh").read_text()
    assert "install -d -o root -g hexstrike -m 0750" in script
    assert "chown root:hexstrike" in script
    assert "chmod 0640" in script
    assert "root:hexstrike:750" in script
    assert "root:hexstrike:640" in script
    assert "chmod 0644" not in script
    assert "chmod 0666" not in script
    assert "chmod 0777" not in script
