# T3 Phase 1 draft readiness runbook

Status: **draft; offline vertical path verified; no live execution authorized**.

## Contract readiness

The Harness sends `POST /api/v1/t3/executions` on loopback with exactly
`authorization_id` and `action_id`. HexStrike resolves all target, credential,
host-key, policy, limit, prerequisite, evidence, and kill-switch values from the
protected runtime. HexStrike alone atomically consumes the approval against the
exact action ID and canonical runtime digest.

The registered adapter families enforce per-action tool-call and duration
bounds. The four migrated legacy capabilities use fixed server-side definitions;
their original endpoints remain disabled with HTTP 410. Results use
`hexstrike-t3-result/v1`; evidence uses
`hexstrike-t3-evidence/v1`, contains only redacted adapter output, is written once
with mode `0600`, and carries a canonical SHA-256 seal.

The bounded Windows/AD assessment family adds seven offline-only actions:
PowerView read-only synthetic directory queries; PowerUp configuration/posture
checks; fixed Seatbelt host categories; WinPEAS audit-only posture; bounded
BloodHound and SharpHound synthetic graph collection; and NetExec authenticated
read-only SMB posture checks. All use protected targets and credential references,
fixed fixture/query/check/collection IDs, one-worker concurrency, bounded rates,
timeouts, object counts, and evidence sizes. Their executor rejects adapters that
are not explicitly marked as offline fakes.

## Offline acceptance gate

Before any later operator proposes live testing, require all of the following:

1. Both repositories remain on their reviewed feature branches with all local
   operator files preserved.
2. Both complete offline suites pass apart from explicitly documented,
   pre-existing local-data failures.
3. The cross-repository contract test passes with fake A/B/C adapters, synthetic
   authorization identifiers, temporary SQLite state, and synthetic evidence.
4. Capability parity reports the unified route and keeps `live_accepted` false.
5. An independent review confirms protected runtime ownership/mode, exact `/32`
   asset binding, pinned host key, identity agent, approval database, evidence
   root, and kill-switch path.

The implemented offline verification commands are:

```text
cd /home/kali/agent-eval-harness
.venv/bin/ruff check .
python -m pytest -q
python scripts/check_t3_capability_parity.py
python scripts/check_t3_capability_parity.py --require-complete

cd /home/kali/hexstrike-ai
/home/kali/agent-eval-harness/.venv/bin/ruff check \
  hexstrike_t3_execution.py tests/test_t3_unified_execution.py
python -m pytest -q
```

The `--require-complete` check is expected to remain nonzero until every declared
catalog family has a bounded implementation and complete offline verification.

## Scope statement

These are selected, partially demonstrated PoC controls. They are not a claim of
full AISVS compliance. Cryptographic approval binding and sandbox/service-identity
isolation remain outside the demonstrated scope.

# LIVE ACTION — HUMAN AUTHORIZATION REQUIRED

No live execution command is included in this Phase 1 draft. A later live section
must remain separately authorized and must not be inferred from offline readiness.

## Stop conditions

Stop without connector invocation if request shape, action registration, runtime
digest, policy, prerequisite evidence seal, approval binding/lifetime, or kill
switch validation fails. Do not treat this draft as permission to contact a
target, authenticate, create a marker, or run any T3 command.
