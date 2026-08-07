# T3-C controlled-impact acceptance (deprecated, not registered)

This historical design is not part of the two-action unified Windows SSH PoC and
is retained only as migration context.

T3-C uses `lab.synthetic-marker.v2` and canonical action
`t3c.controlled_impact_proof.v1`. Harness validates sealed successful T3-A and T3-B
results, verifies that T3-B binds to the T3-A run ID and trace fingerprint, consumes a
separate approval, and sends only `authorization_id` and `canonical_action` to
`POST /api/v1/t3c/executions` on `127.0.0.1:8888`.

HexStrike resolves the single asset, target, credential/identity references, pinned
host-key file, marker path, expected digest, and limits from protected server-side
configuration. The fixed lifecycle is absence check → create → existence and digest
proof → cleanup → absence verification. A pre-existing marker is not removed. Proof
failure enters cleanup; cleanup or absence-verification failure is an overall failure
with a sanitized operator warning.

The sanitized templates are `config/example/t3c-runtime.json` in Harness and
`t3c-runtime.example.json` in HexStrike. Documentation addresses and angle-bracket
values are not operational configuration. The HexStrike loader requires exact schema,
profile `poc`, asset `asset:winsrv2025-01`, scenario, fixed path/digest, limits, and all
three readiness assertions. Its default protected file must be root-owned,
group-owned by `hexstrike`, and mode `0640`. Missing configuration does not prevent
route registration or common listener startup, but the T3-C request fails closed.

Offline readiness (no connector invocation):

```bash
cd /home/kali/agent-eval-harness
.venv/bin/python scripts/verify_t3c_readiness.py \
  --runtime-config <PROTECTED_HARNESS_T3C_CONFIG> \
  --hexstrike-config <PROTECTED_HEXSTRIKE_T3C_CONFIG> \
  --t3a-result <SEALED_T3A_RUN_DIR>/result.json \
  --t3b-result <SEALED_T3B_RUN_DIR>/result.json \
  --approval-spent-dir <APPROVAL_SPENT_DIR> \
  --approval-token-file <NEW_T3C_APPROVAL_TOKEN_PATH> \
  --kill-switch-file <KILL_SWITCH_PATH>
```

Approval and execution commands are documented in `docs/t3-live-test-runbook.md` and
must be run only by an authorized human. Success is `completed: true`,
`status: succeeded`, and true values for initial absence, creation, proof, cleanup,
and rollback verification.

Current checkpoint status: T3-A and T3-B remain implemented and offline-tested, ready
for human live-test preparation. T3-C is a single-asset reversible scenario. Listener
deployment and live target testing are separate authorized checkpoints.

This T3-C scenario validates a reversible controlled-impact operation on one approved
isolated asset. It does not test or claim cross-host lateral movement.

This research PoC implements selected applicable AISVS controls. It does not claim
complete conformity with AISVS Level 1, Level 2, or Level 3.
