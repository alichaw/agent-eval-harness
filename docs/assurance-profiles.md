# Decision: dual T3 assurance profiles

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
It never sends an assurance-profile selector. HexStrike must enable those
routes only through its own trusted startup profile and only on loopback.
Deploying that matching HexStrike endpoint is required before live PoC
acceptance; the Harness does not fall back to a generic tool endpoint.

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
