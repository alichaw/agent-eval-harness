# Decision: dual T3 assurance profiles

> Deprecated compatibility note: the current production PoC startup registers
> only the unified two-action Windows SSH route. The legacy profile-specific
> T3-A/B/C modules remain unregistered migration fixtures.

## Status

Accepted for the research PoC. This decision does not authorize production use
of the `poc` profile.

## Decision

T3 supports exactly two operator-selected assurance profiles:

- `poc` is the research and internship acceptance profile.
- `hardened` preserves the higher-assurance execution-permit and deployment
  controls.

The profile is loaded once from the mode-0600 operator T3 runtime JSON:

```json
{"assurance": {"profile": "poc"}}
```

Omitting `assurance` selects `hardened`. Unknown values and additional keys are
rejected. Agent proposals, task specifications, approval payloads, tool
parameters, and ordinary CLI arguments cannot select the profile.

## Shared mandatory controls

Both profiles retain default-deny policy, approved assets, deny precedence,
fixed tools and parameters, identifier-only agent proposals, explicit T3 human
approval, canonical approval presentation, single-use approval, replay
prevention, credential references, post-authorization credential resolution,
kill switch, bounded sessions/output/time, loopback HexStrike configuration,
and sealed traces/results.

Changing an asset, profile, action, target binding, registry definition,
credential reference, or execution limit after approval remains a denial.

## Profile-specific controls

`hardened` requires the existing signed execution permit, signature and context
binding, nonce consumption, signing-key isolation, dedicated `hexstrike`
identity, hardened systemd deployment, and UID network enforcement. A missing
requirement is `FAIL`.

For `poc`, these controls are outside the acceptance scope:

- cryptographically bound downstream execution permits (AISVS 9.2.8);
- isolation of approval-signing credentials (AISVS 9.2.9);
- downstream delegation tokens (AISVS 9.5.2);
- dedicated executor identity;
- hardened systemd deployment;
- UID-level network enforcement.

Readiness records each as `SKIPPED_BY_PROFILE`; it never reports them as
`PASS`. Common controls remain mandatory and runtime errors remain `FAIL`.

The signed-permit implementation is not removed or weakened. Selecting `poc`
does not make an absent or malformed signed permit valid in the hardened
endpoint. The Harness uses the separate fixed
`/api/v1/t3a/poc-executions`/`/api/v1/t3b/poc-executions` adapter paths and
sends only the post-approval canonical action plus an audit authorization ID.
It never sends an assurance-profile selector. HexStrike enables those routes
only when its protected service environment sets
`HEXSTRIKE_ASSURANCE_PROFILE=poc`; missing or unknown values never enable PoC
routes. The root-owned `root:hexstrike` mode `0640`
`/etc/hexstrike/t3-poc-runtime.json` binds the same asset, target-binding
digest, and pinned host key. Requests contain only an authorization ID and the
fixed operation ID. Target, port, credential reference, username, identity
agent, pinned key, commands, and limits are resolved from protected server
state. HexStrike atomically rejects reuse of a PoC authorization ID. The
Harness does not fall back to a generic tool endpoint.

The protected files have separate responsibilities:

- Harness `config/local/t3-runtime.json` selects the trusted assurance profile
  and binds T3-A/T3-B orchestration to the registered asset and credential
  reference. It remains mode `0600` and is never read by HexStrike.
- `/etc/hexstrike/t3-reachability.json` contains exactly `asset_id`, resolved
  `target`, and fixed `port: 22`; it is shared preflight state.
- `/etc/hexstrike/t3-poc-runtime.json` contains exactly
  `assurance_profile: poc`, `asset_id`, the approved `target_binding` digest,
  and `pinned_host_key`. It is the common T3-A/T3-B unsigned PoC execution
  binding.
- `/etc/hexstrike/job-targets.json` contains exactly the approved target `/32`
  used by T3-A/T3-B, while `/etc/hexstrike/t3a-credentials.json` maps the fixed
  credential reference to the same asset, low-privilege username, and protected
  identity-agent socket.

The identity-agent value is fixed by
`config/t3-identity-agent-runtime.json` and the repository-owned
`hexstrike-t3-ssh-agent.service`. Both PoC and hardened HexStrike units depend on that
service and receive its stable socket through an explicit service environment
binding. Neither profile may inherit a transient operator-shell agent, substitute a
private-key path, or fall back to the other profile. Socket availability and identity
provisioning are reported as distinct readiness states.
- `/etc/hexstrike/t3c-runtime.json` is separate scenario state for
  `t3c.controlled_impact_proof.v1`. It contains one fixed asset and target,
  credential and identity references, pinned-known-hosts path, fixed marker path
  and digest, bounded limits, and cleanup, rollback-verification, and isolated-lab
  readiness assertions. It does not replace the common PoC runtime.

Every `/etc/hexstrike/*.json` file above is required to be
`root:hexstrike 0640`. The PoC unit names both
`HEXSTRIKE_T3_POC_RUNTIME_CONFIG` and `HEXSTRIKE_T3C_CONFIG`; the former
controls common T3-A/T3-B execution and the latter controls only T3-C.

In the supported Harness flow, PoC authorization IDs are created only after the
Harness atomically consumes a fresh stage-specific human approval. The opaque
ID carries a 60-second issue time and a T3-A, T3-B, or T3-C stage tag.
HexStrike validates the tag and age, then consumes it in one shared SQLite database at
`/var/lib/hexstrike/spent-poc-authorizations.sqlite3`. A primary-key insert
under an immediate transaction gives at most one consumer during concurrent
requests and persists across service restart. The ID is not a signed
delegation token, so HexStrike cannot independently prove that an otherwise
well-formed fresh ID originated from the Harness approval flow. That downstream
provenance control remains `SKIPPED_BY_PROFILE` and the PoC relies on loopback
exposure plus operating-system access control. The fixed route plus protected
server configuration constrains any accepted request to the only permitted
asset, action, credential context, commands, and limits; it does not turn the
opaque ID into a cryptographic action or asset binding.

Offline tests prove the implementation and atomic replay behavior. T3-A and T3-B
are ready for human live-test preparation. T3-C is implemented as a single-asset
reversible scenario and is ready for protected runtime installation and human
live-test preparation. Listener binding, service-account file access, protected
runtime metadata, and real T3-A/T3-B/T3-C execution remain awaiting separately
authorized operator verification.

This T3-C scenario validates a reversible controlled-impact operation on one
approved isolated asset. It does not test or claim cross-host lateral movement.

## Readiness semantics

Each check reports `PASS`, `FAIL`, or `SKIPPED_BY_PROFILE`, with the active
profile, reason, timestamp, and applicable AISVS reference. Overall readiness
is:

- `ready=false` if any mandatory check is `FAIL`;
- `ready=true, ready_with_profile_skips=true` for a valid PoC configuration
  containing authorized skips;
- production-ready only for a fully verified `hardened` configuration.

`t3-ready` remains credential-free and target-offline. It validates the
configured HexStrike URL as exactly `http://127.0.0.1:8888`. The privileged
operator verifier described in `docs/t3-operator-readiness.md` separately
verifies the actual listener and hardened OS controls.

## T3-A acceptance

1. Configure the protected runtime file with the operator-selected assurance
   profile.
2. Run `t3-ready` and retain its structured result.
3. Review the canonical approval presentation: asset, resolved-target identity,
   stage, profile, fixed action IDs, justification, runtime-binding fingerprint,
   and assurance profile.
4. Issue a short-lived approval.
5. Execute one bounded T3-A run. Credential resolution occurs only after
   approval consumption.
6. Confirm only the registered identity/host/privilege-status actions ran.
7. Replay and verify the sealed manifest, trace, and result.
8. Confirm approval reuse and post-approval mutation are rejected.

No arbitrary shell, SSH options, password guessing, exploitation, privilege
escalation, credential dumping, persistence, or lateral movement is authorized.

## Assurance statement

This project uses an AISVS Level 1 baseline with selected Level 2
runtime-authorization controls for the current research PoC. It does not claim
complete conformity with AISVS Level 2 or Level 3.

Cryptographically bound execution permits, isolated approval-signing keys,
downstream delegation tokens, dedicated executor identity, and UID-level
network enforcement are deferred from the current PoC acceptance scope and
remain part of the hardened profile.

The `poc` profile is not approved for production use.

## Restoring hardened deployment

Set `{"assurance":{"profile":"hardened"}}` in the protected runtime file,
provision the protected permit verifier secret, deploy HexStrike under its
dedicated hardened service, apply and verify UID default-deny egress policy,
and require every hardened readiness check to report `PASS`. After the
privileged verifier succeeds, the operator may create the exact root-owned mode
0600 attestation `/etc/agent-eval-harness/hardened-readiness.json` containing
only `{"uid_network_enforcement":true,"verified_at":"<UTC ISO-8601>"}`. It is
accepted for 15 minutes, is an OS-control attestation rather than Agent input,
and must never be created before verification. Never convert a failed hardened
check into a profile skip.
