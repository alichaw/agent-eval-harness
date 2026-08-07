from pathlib import Path


def test_poc_service_unit_is_explicit_and_has_no_permit_environment():
    unit = Path("config/systemd/hexstrike-t3-poc.service").read_text()
    assert "User=hexstrike" in unit
    assert "Group=hexstrike" in unit
    assert "Environment=HEXSTRIKE_HOST=127.0.0.1" in unit
    assert "Environment=HEXSTRIKE_PORT=8888" in unit
    assert "Environment=HEXSTRIKE_ASSURANCE_PROFILE=poc" in unit
    assert (
        "Environment=HEXSTRIKE_T3_UNIFIED_RUNTIME_CONFIG=/etc/hexstrike/t3-unified-runtime.json"
    ) in unit
    assert "HEXSTRIKE_T3_POC_RUNTIME_CONFIG" not in unit
    assert "HEXSTRIKE_T3C_CONFIG" not in unit
    assert "EnvironmentFile=" not in unit
    assert "PERMIT_SECRET" not in unit
    assert "StateDirectory=hexstrike" in unit
    assert "WorkingDirectory=/opt/hexstrike-t3-poc/app" in unit
    assert (
        "ExecStart=/opt/hexstrike-t3-poc/venv/bin/python3 "
        "/opt/hexstrike-t3-poc/app/hexstrike_t3_app.py"
    ) in unit
    assert "ReadOnlyPaths=/opt/hexstrike-t3-poc /etc/hexstrike" in unit
    assert "ReadWritePaths=/var/lib/hexstrike /run/hexstrike" in unit
    assert "ProtectSystem=strict" in unit
    assert "ProtectHome=true" in unit
    assert "Requires=hexstrike-t3-ssh-agent.service" in unit
    assert "After=network.target hexstrike-t3-ssh-agent.service" in unit
    assert "Environment=SSH_AUTH_SOCK=/run/hexstrike-t3-ssh-agent/agent.sock" in unit
    assert "/home/kali" not in unit


def test_repository_owned_identity_agent_unit_and_contract_are_fixed():
    unit = Path("config/systemd/hexstrike-t3-ssh-agent.service").read_text()
    contract = __import__("json").loads(Path("config/t3-identity-agent-runtime.json").read_text())
    assert contract["unit_name"] == "hexstrike-t3-ssh-agent.service"
    assert contract["socket_path"].startswith("/run/")
    assert contract["socket_path"].startswith(contract["runtime_directory"] + "/")
    assert "User=hexstrike" in unit
    assert "Group=hexstrike" in unit
    assert "RuntimeDirectoryMode=0700" in unit
    assert f"RuntimeDirectory={Path(contract['runtime_directory']).name}" in unit
    assert f"ExecStart=/usr/bin/ssh-agent -D -a {contract['socket_path']}" in unit
    assert "UMask=0077" in unit
    assert "/tmp" not in unit
    assert "private_key" not in unit
