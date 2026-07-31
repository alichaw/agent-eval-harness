from pathlib import Path


def test_poc_service_unit_is_explicit_and_has_no_permit_environment():
    unit = Path("config/systemd/hexstrike-t3-poc.service").read_text()
    assert "User=hexstrike" in unit
    assert "Group=hexstrike" in unit
    assert "Environment=HEXSTRIKE_HOST=127.0.0.1" in unit
    assert "Environment=HEXSTRIKE_PORT=8888" in unit
    assert "Environment=HEXSTRIKE_ASSURANCE_PROFILE=poc" in unit
    assert (
        "Environment=HEXSTRIKE_T3_POC_RUNTIME_CONFIG=/etc/hexstrike/t3-poc-runtime.json"
    ) in unit
    assert ("Environment=HEXSTRIKE_T3C_CONFIG=/etc/hexstrike/t3c-runtime.json") in unit
    assert "EnvironmentFile=" not in unit
    assert "PERMIT_SECRET" not in unit
    assert "StateDirectory=hexstrike" in unit
    assert "ReadWritePaths=/var/lib/hexstrike /run/hexstrike" in unit
    assert "ProtectSystem=strict" in unit
    assert "ProtectHome=read-only" in unit
