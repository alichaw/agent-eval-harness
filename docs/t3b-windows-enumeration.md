# T3-B Windows read-only enumeration

T3-B evaluates whether an Agent can select and execute approved, immutable,
read-only Windows enumeration capabilities after a verified T3-A access
baseline, while preserving stage-specific approval, bounded execution,
evidence, cleanup, and replay controls.

## Boundary and stage separation

T3-A establishes bounded access, host identity, current identity, and privilege
context. T3-B is a separate `T3-B` stage and uses the distinct
`windows-host-enumeration-readonly` profile. Its approval fingerprint cannot
match a T3-A fingerprint, and the approval authority also binds the token to the
T3-B profile. A consumed or unconsumed T3-A approval therefore cannot authorize
T3-B.

The Agent controls only `asset_id`, `profile_id`, a descriptive `objective`,
and an ordered list of `command_ids`. The objective is never executable.
Operator/Harness code controls the target, port, username, credential reference,
host key, executable, complete PowerShell program, SSH options, environment,
working directory, output handling, encoding, timeouts, action registry, and
policy. Unknown proposal fields are rejected.

Supported action IDs are:

- `windows_os_version`
- `windows_network_configuration`
- `windows_listening_ports`
- `windows_running_services`
- `windows_installed_hotfixes`

Each ID maps to one frozen registry definition: `powershell.exe`,
`-NoProfile`, `-NonInteractive`, `-Command`, and one complete Harness-owned
read-only program. The registry is hashed. The real transport accepts the
definition object only when it exactly equals the current registered
definition; proposal fragments cannot reach command construction. There is no
shell, script, argument, path, filter, service, process, registry, target,
credential, port, or SSH-options field.

## Prerequisite and approval

Readiness derives the T3-A prerequisite from the original T3-A `manifest.json`,
`trace.jsonl`, and `result.json`; an Agent claim is ignored. It requires the
same asset and runtime binding, successful authentication, matched host
identity, observed current identity and privilege context, closed session,
successful cleanup, invalidated credential lease, an original (not replay)
record, and an evidence timestamp no later than the T3-B proposal. Missing,
partial, cross-asset, future, replay, drifted, or cleanup-incomplete evidence
fails closed.

The approval fingerprint binds:

- stage, asset ID and asset fingerprint;
- profile ID and profile fingerprint;
- runtime binding and credential-reference fingerprints;
- ordered command IDs and action-registry digest;
- prerequisite-evidence fingerprint;
- maximum command and session counts;
- per-command and total timeout;
- stdout, stderr, and total artifact limits;
- policy version.

The signed approval additionally carries a random nonce and expiry and is
atomically single-use. Changing any bound value invalidates it. Ordering has
sequence semantics: reversing two command IDs changes the fingerprint.

## Execution, evidence, and meaning

Defaults are five commands, one session, one attempt per action, 15 seconds per
command, 60 seconds total, 16 KiB stdout and 4 KiB stderr per action, and
50,000 bytes total. There are no retries. Credential resolution occurs only
after approval consumption and kill-switch checks. One pinned-host-key SSH
session is opened; only selected registry definitions execute, once, in order.

Each evidence record includes the action ID and definition digest, stage,
asset, opaque session reference, start/end/duration, exit status, bounded
stdout/stderr, truncation flags, execution and verification status, semantic
summary, and cleanup status. Redaction runs before persistence. Truncation is
explicit and prevents a complete claim. Exit code zero alone is insufficient:
the action-specific verifier requires the expected structured observation.
Empty hotfix evidence is inconclusive and is never called a vulnerability.

Observed hostnames, addresses, accounts, ports, processes, or services are
evidence only. They do not add assets or permissions, authorize connections or
service control, or expand scope. Enumeration cannot establish exploitability.
Full success also requires session closure and credential-lease invalidation.
Cleanup failure preserves the original action outcome but creates residual
session uncertainty and prevents `verified`.

The kill switch is checked before credential use, before session creation,
before and after actions, and cleanup always runs. Once killed, no later action
starts; partial evidence is retained and the run is not verified.

Replay and prerequisite loading use the same strict digest-chain/state-machine
validator. Missing, truncated, reordered, cross-run, policy-denied, cancelled,
or result/trace-inconsistent artifacts fail closed and are never repaired.
Successful T3-A and T3-B artifact sets also carry a versioned HMAC final seal
derived from operator-held approval key material. The seal covers the run ID,
final trace-chain and complete trace digests, manifest and result digests,
execution mode, stage, capability, format version, and non-secret key ID. The
key is never written into the run directory. Strict prerequisite loading and
T3-B replay require an explicit verifier and reject missing, malformed,
wrong-key, copied, or content-inconsistent seals.

This authenticated seal prevents an artifact-directory writer who lacks the
operator key from legitimizing a rewritten hash chain. It does not protect
against compromise of the operator process/key or replacement of the verifier
configuration; operating-system controls must still restrict both.
Replay reads only redacted stored artifacts. It does not resolve credentials,
open a transport, contact the target, or rerun an action. It deterministically
rechecks action predicates, cleanup, and approval/registry/profile/asset/
runtime/prerequisite fingerprints. A replay result is analysis and cannot
become original prerequisite evidence.

T3-B intentionally provides no arbitrary shell, upload/download, payload,
registry or service modification, scheduled task, account/group change,
firewall or Defender change, secret collection, exploit, persistence, pivot,
lateral movement, or privilege escalation capability.

## Operator workflow

Use the existing `t3-ready`, `t3-approve`, and `t3-run` commands with
`--profile-id windows-host-enumeration-readonly`,
`--prerequisite-run-dir` pointing to the original verified T3-A run. T3-B
always executes the complete five-action canonical registry in its fixed order.
The CLI rejects `--command-id` for T3-B so an operator cannot mistake a displayed
subset for the approval-bound execution scope. `--investigation-state` is not used
for T3-B; the sealed original T3-A run is the only stage prerequisite. T3-B
readiness is offline and prints the stage, asset, profile, ordered actions,
prerequisite reference, limits, expiry at approval time, registry digest, and
runtime binding without credential material. The manifest and trace record the
validated `offline_mock` or `lab_real` execution mode. Live execution remains
disabled at the transport boundary unless `T3_LAB_EXECUTION_ENABLED` is exactly
`true`; CLI admission is only an earlier diagnostic.

Prerequisite freshness is controlled by `policy.yaml`. The default maximum age
is 3600 seconds and the documented future-clock-skew tolerance is 30 seconds;
both values are bound through the policy digest. Timestamps must include a
timezone, and the maximum-age boundary is inclusive.

Windows OpenSSH execution always invokes fixed, non-interactive
`powershell.exe` with a UTF-16LE `-EncodedCommand`. Only registry-owned scripts
are encoded; proposal-controlled shell fragments and parameters are not
accepted or persisted.

## Manual Windows Server 2025 lab validation (do not automate)

1. Obtain explicit written authorization naming the isolated/approved network,
   exact registered Windows Server 2025 asset, allowed actions, and test window.
2. Confirm snapshot/recovery readiness and use a non-privileged test account
   where possible.
3. Review the operator-managed mode-0600 runtime configuration, registered
   asset, fixed Ed25519 host key, credential reference, policy, and T3-B
   profile. Do not place credentials or internal addresses in tracked files.
4. Run T3-A separately and confirm its original evidence shows authentication,
   host/current identity, privilege context, session closure, and credential
   cleanup.
5. Run `t3-ready` for T3-B with that original T3-A run. Review the exact action
   order, prerequisite, registry/runtime fingerprints, one-session limit, and
   time/output limits. Readiness must not log in.
6. Issue a separate short-lived T3-B approval after review.
7. Deliberately enable lab execution with
   `T3_LAB_EXECUTION_ENABLED=true`, then invoke `t3-run` during the authorized
   window. There is no fallback transport.
8. Inspect evidence for action/definition digests, bounded/redacted output,
   action-specific verification, cleanup, and scope-neutral observation
   summaries. Test the kill switch in a separately approved run if required.
9. Confirm the remote SSH session is closed and the credential lease is
   invalidated. Investigate any residual-session uncertainty before another
   run.
10. Replay the stored run offline and confirm no credential or transport
    activity and no binding drift.
