import base64
import json

from core.safety import KillSwitch
from core.t3.enumeration import WINDOWS_ACTION_REGISTRY, T3BAgentProposal
from core.t3.hexstrike_enumeration import HexStrikeT3BExecutor
from tests.test_t3_enumeration import plan


def executor(session, tmp_path, *, enablement="true"):
    return HexStrikeT3BExecutor(
        base_url="http://127.0.0.1:8888",
        permit_secret=b"synthetic-t3b-permit-secret-32bytes",
        enablement=enablement,
        kill_switch=KillSwitch(tmp_path / "KILL"),
        session=session,
    )


def test_agent_t3b_proposal_contains_only_asset_and_profile():
    proposal = T3BAgentProposal(
        asset_id="asset:winsrv2025-01",
        profile_id="windows-host-enumeration-readonly",
    )
    assert set(proposal.model_dump()) == {"asset_id", "profile_id"}
    assert proposal.as_trusted_proposal().command_ids == list(WINDOWS_ACTION_REGISTRY)


def test_disabled_and_killed_t3b_never_call_hexstrike(tmp_path):
    class NoNetwork:
        calls = 0

        @classmethod
        def post(cls, *args, **kwargs):
            cls.calls += 1
            raise AssertionError("network called")

    assert executor(NoNetwork, tmp_path, enablement=None).run(plan()).status == (
        "lab_execution_disabled"
    )
    (tmp_path / "KILL").touch()
    assert executor(NoNetwork, tmp_path).run(plan()).status == "kill_switch_engaged"
    assert NoNetwork.calls == 0


def test_missing_permit_secret_never_calls_hexstrike(tmp_path):
    class NoNetwork:
        calls = 0

        @classmethod
        def post(cls, *args, **kwargs):
            cls.calls += 1
            raise AssertionError("network called")

    selected = HexStrikeT3BExecutor(
        base_url="http://127.0.0.1:8888",
        permit_secret=b"",
        enablement="true",
        kill_switch=KillSwitch(tmp_path / "KILL"),
        session=NoNetwork,
    )
    assert selected.run(plan()).status == "execution_permit_secret_unavailable"
    assert NoNetwork.calls == 0


def test_hexstrike_failure_and_malformed_response_have_no_fallback(tmp_path):
    class Unavailable:
        calls = 0

        @classmethod
        def post(cls, *args, **kwargs):
            cls.calls += 1
            raise OSError("synthetic")

    selected = executor(Unavailable, tmp_path)
    assert selected.run(plan()).status == "hexstrike_unavailable"
    assert Unavailable.calls == 1

    class Malformed:
        @staticmethod
        def post(*args, **kwargs):
            class Response:
                status_code = 200

                @staticmethod
                def json():
                    return {"status": "verified"}

            return Response()

    assert executor(Malformed, tmp_path).run(plan()).status == "hexstrike_response_invalid"


def test_schema_valid_hexstrike_result_is_verified_and_permit_bound(tmp_path):
    observations = {
        "windows_os_version": {
            "Caption": "Windows Server",
            "Version": "synthetic",
            "BuildNumber": "synthetic",
        },
        "windows_network_configuration": {"InterfaceAlias": "synthetic"},
        "windows_listening_ports": {"LocalAddress": "synthetic", "LocalPort": 22},
        "windows_running_services": {"Name": "synthetic", "Status": "Running"},
        "windows_installed_hotfixes": {"HotFixID": "synthetic"},
    }
    selected_plan = plan(
        p=T3BAgentProposal(
            asset_id="asset-1",
            profile_id="windows-host-enumeration-readonly",
        ).as_trusted_proposal()
    )

    class Loopback:
        calls = 0

        @classmethod
        def post(cls, url, *, json, timeout):
            cls.calls += 1
            payload = json["permit"].split(".", 1)[0]
            payload += "=" * (-len(payload) % 4)
            claims = json_module.loads(base64.urlsafe_b64decode(payload))
            results = []
            for definition in selected_plan.definitions:
                stdout = json_module.dumps(observations[definition.action_id.value])
                results.append(
                    {
                        "action_id": definition.action_id.value,
                        "definition_digest": definition.digest,
                        "started_at": "2026-07-30T00:00:00+00:00",
                        "completed_at": "2026-07-30T00:00:01+00:00",
                        "duration_seconds": 1.0,
                        "exit_status": 0,
                        "stdout": stdout,
                        "stderr": "",
                        "stdout_original_bytes": len(stdout.encode()),
                        "stdout_retained_bytes": len(stdout.encode()),
                        "stderr_original_bytes": 0,
                        "stderr_retained_bytes": 0,
                        "stdout_truncated": False,
                        "stderr_truncated": False,
                        "stdout_decoding_errors": False,
                        "stderr_decoding_errors": False,
                    }
                )

            class Response:
                status_code = 200

                @staticmethod
                def json():
                    return {
                        "schema_version": "hexstrike-t3b-result/v1",
                        "permit_id": claims["permit_id"],
                        "operation_id": "windows.host.enumeration.readonly.v1",
                        "status": "verified",
                        "authentication_succeeded": True,
                        "session_closed": True,
                        "cleanup_succeeded": True,
                        "credential_lease_invalidated": True,
                        "action_results": results,
                    }

            return Response()

    json_module = json
    outcome = executor(Loopback, tmp_path).run(selected_plan)
    assert outcome.status == "verified"
    assert outcome.completed is True
    assert outcome.execution_permit_id
    assert len(outcome.execution_permit_digest) == 64
    assert len(outcome.action_evidence) == len(WINDOWS_ACTION_REGISTRY)
    assert Loopback.calls == 1
