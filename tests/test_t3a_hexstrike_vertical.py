from core.t3.access import (
    BoundedLabSshExecutionPlan,
    T3AccessProposal,
    T3AuthorizedAccessProposal,
    T3CommandId,
)
from core.t3.assurance import AssuranceContext, AssuranceProfile
from core.t3.hexstrike_access import T3A_COMMANDS, HexStrikeT3AExecutor

SECRET = b"synthetic-execution-permit-secret"
TARGET = "192.0.2.25"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"


def plan(**updates):
    values = {
        "action_id": "action",
        "source_asset_id": "asset:winsrv2025-01",
        "profile_id": "t3-authorized-access-bounded",
        "target": TARGET,
        "port": 22,
        "credential_handle": "credential:ssh-winsrv2025-01",
        "pinned_host_key": HOST_KEY,
        "command_ids": tuple(T3CommandId(item.value) for item in T3A_COMMANDS),
    }
    values.update(updates)
    return BoundedLabSshExecutionPlan(**values)


def executor(session, *, enablement="true", kill_switch=None):
    return HexStrikeT3AExecutor(
        base_url="http://127.0.0.1:8888",
        permit_secret=SECRET,
        enablement=enablement,
        permitted_target=TARGET,
        kill_switch=kill_switch,
        approval_fingerprint="a" * 64,
        runtime_binding_fingerprint="b" * 64,
        session=session,
    )


class NoNetwork:
    calls = 0

    @classmethod
    def post(cls, *args, **kwargs):
        cls.calls += 1
        raise AssertionError("network called")


def test_enablement_and_runtime_drift_deny_before_hexstrike():
    NoNetwork.calls = 0
    assert executor(NoNetwork, enablement=None).run(plan()).rule == "lab_execution_disabled"
    assert executor(NoNetwork).run(plan(target="192.0.2.26")).rule == "runtime_binding_mismatch"
    assert executor(NoNetwork).run(plan(port=2222)).rule == "runtime_binding_mismatch"
    assert (
        executor(NoNetwork).run(plan(command_ids=(T3CommandId.CURRENT_IDENTITY,))).rule
        == "runtime_binding_mismatch"
    )
    assert NoNetwork.calls == 0


def test_hexstrike_unavailable_has_no_fallback():
    class Unavailable:
        calls = 0

        @classmethod
        def post(cls, *args, **kwargs):
            cls.calls += 1
            raise OSError("synthetic")

    selected = executor(Unavailable)
    assert selected.run(plan()).rule == "hexstrike_unavailable"
    assert Unavailable.calls == 1
    assert selected.invocation_count == 1


def test_malformed_hexstrike_response_fails_closed():
    class Session:
        @staticmethod
        def post(*args, **kwargs):
            class Response:
                status_code = 200

                @staticmethod
                def json():
                    return {"status": "completed"}

            return Response()

    assert executor(Session).run(plan()).rule == "hexstrike_response_invalid"


def test_proposal_rejects_raw_execution_fields():
    for field in ("target", "port", "raw_command", "command", "powershell", "args"):
        try:
            T3AccessProposal(
                asset_id="asset:winsrv2025-01",
                profile_id="t3-authorized-access-bounded",
                objective="bounded identity",
                command_ids=["current_identity"],
                **{field: "whoami; hostname"},
            )
        except Exception:
            continue
        raise AssertionError(f"proposal accepted forbidden field {field}")


def test_agent_authorized_access_proposal_contains_only_asset_and_profile():
    proposal = T3AuthorizedAccessProposal(
        asset_id="asset:winsrv2025-01",
        profile_id="t3-authorized-access-bounded",
    )
    assert set(proposal.model_dump()) == {"asset_id", "profile_id"}
    trusted = proposal.as_trusted_access_proposal()
    assert trusted.command_ids == list(T3A_COMMANDS)


def test_poc_uses_fixed_unsigned_authorization_endpoint_without_permit_secret():
    class PocSession:
        calls = []

        @classmethod
        def post(cls, url, *, json, timeout):
            cls.calls.append((url, json))
            authorization_id = json["authorization_id"]

            class Response:
                status_code = 200

                @staticmethod
                def json():
                    return {
                        "schema_version": "hexstrike-t3a-poc-result/v1",
                        "authorization_id": authorization_id,
                        "operation_id": "windows.ssh.identity.v1",
                        "status": "completed",
                        "authentication_succeeded": True,
                        "session_closed": True,
                        "cleanup_succeeded": True,
                        "credential_lease_invalidated": True,
                        "command_results": [
                            {
                                "command_id": command.value,
                                "attempted": True,
                                "return_code": 0,
                                "outcome": "succeeded",
                                "sanitized_stdout": "synthetic",
                                "duration_seconds": 0.1,
                                "evidence_predicate_passed": True,
                            }
                            for command in T3A_COMMANDS
                        ],
                    }

            return Response()

    selected = HexStrikeT3AExecutor(
        base_url="http://127.0.0.1:8888",
        permit_secret=b"",
        enablement="true",
        permitted_target=TARGET,
        kill_switch=None,
        approval_fingerprint="a" * 64,
        runtime_binding_fingerprint="b" * 64,
        assurance=AssuranceContext(AssuranceProfile.POC),
        session=PocSession,
    )
    outcome = selected.run(plan())
    assert outcome.completed
    assert outcome.execution_permit_id == ""
    assert "signed_execution_permit_skipped_by_profile" in outcome.trace_codes
    assert PocSession.calls[0][0].endswith("/api/v1/t3a/poc-executions")
    request = PocSession.calls[0][1]
    assert set(request) == {"authorization_id", "canonical_action"}
    assert "permit" not in request
    assert "assurance_profile" not in request
