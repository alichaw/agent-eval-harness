from pathlib import Path


def test_installer_preserves_protected_non_root_deployment_contract():
    script = Path("scripts/install_hexstrike_t3_poc.sh").read_text()
    assert "install_root=/opt/hexstrike-t3-poc" in script
    assert "chown root:hexstrike" in script
    assert "chmod 0750" in script
    assert "chmod 0600" in script
    assert "runuser -u hexstrike -- test -r" in script
    assert "runuser -u hexstrike -- test -x" in script
    assert "protected_runtime=t3-unified-runtime.json" in script
    assert "systemd-analyze verify" in script
    assert "systemctl daemon-reload" in script
    assert "systemctl start" not in script
    assert "assets.yaml" not in script
    assert "sed -i" not in script


def test_installer_copies_an_explicit_application_allowlist():
    script = Path("scripts/install_hexstrike_t3_poc.sh").read_text()
    assert 'application_files="hexstrike_t3_app.py ' in script
    assert "hexstrike_t3_execution.py" in script
    assert "hexstrike_t3a.py" not in script
    assert "hexstrike_t3c.py" not in script
    assert "cp -R" not in script
    assert "hexstrike_server.log" not in script
    assert ".example.json" not in script


def test_installer_has_identity_only_bootstrap_without_service_start():
    script = Path("scripts/install_hexstrike_t3_poc.sh").read_text()
    assert "--bootstrap-identity" in script
    assert "phase=service_identity_only" in script
