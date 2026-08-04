# Canonical Windows SSH reachability investigation state

`harness t3-state` is the production state producer for authorized T3-A on a
registered Windows OpenSSH lab host. It reuses `InvestigationState` and
`record_step_result()`; it does not use a test fixture or accept caller-supplied
evidence.

The operator supplies only an asset ID and trusted configuration paths. The Harness
resolves the target from `AssetRegistry`, requires the
`windows-ssh-reachability-check` profile, checks denied targets before the allowlist,
and refuses to run when the operator denied-CIDR list is empty. The fixed action is
`t3a.ssh22_reachability.v1`: one TCP connection attempt to port 22. It does not read
the T3 credential reference, private key, password, or SSH agent and never performs
an SSH handshake/login.

HexStrike resolves the same fixed asset through its protected
`/etc/hexstrike/t3-reachability.json` file:

```json
{
  "asset_id": "asset:winsrv2025-01",
  "target": "OPERATOR_AUTHORIZED_TARGET",
  "port": 22
}
```

The production service requires this file to be owned by `root:hexstrike` with
mode `0640`. Its schema is exact: additional keys are rejected. The target must
be copied from the Harness `AssetRegistry`, never supplied on a CLI or endpoint
request.

The containing `/etc/hexstrike` directory must be `root:hexstrike` mode `0750` so
the non-root service can traverse it without making protected files world-readable.
Apply or validate this contract idempotently with
`scripts/setup_t3_poc_config_permissions.sh --apply` or `--check`. The loader opens
files without following symlinks, validates the opened descriptor as a regular file
with exact `root:hexstrike 0640` metadata, and only then parses JSON. Missing,
unreadable, malformed, wrong-owner, wrong-group, or wrong-mode files fail closed with
a sanitized filename and expected-metadata diagnostic.

PoC T3-A/T3-B action configuration is loaded lazily after request-scope and
authorization validation. Missing unrelated action configuration therefore cannot
prevent the fixed reachability route from starting, while action execution remains
fail closed.

The endpoint accepts only `action_id` and `asset_id`. Structured output contains
exactly asset, port 22, TCP, SSH, and one state: `reachable`, `unreachable`, or
`error`, plus a safe target-binding digest. The Harness recomputes that digest from
`AssetRegistry`, so a protected HexStrike configuration pointing at any other target
is rejected without recording the raw address. Only `reachable` becomes complete
evidence. Missing fields, unknown states, unreachable, transport errors, policy
denial, unknown assets, or an active kill switch fail closed and cannot satisfy T3-A.

Real probing requires the explicit `--confirm-lab-probe` flag. Tests inject a fake
executor and perform no network activity.

Before use, the operator must populate real company, production, management, VPN,
and other excluded CIDRs in ignored `config/local/policy.yaml`. Example CIDRs are
documentation only and must never be treated as authorization.

For the explicitly authorized single-asset research PoC, an operator may first use
a documented minimum boundary covering IPv4/IPv6 loopback, link-local, cloud
metadata, multicast, unspecified/reserved and documentation ranges. When the sole
approved lab target is a public IP, this minimum also denies RFC1918, shared address
space, and IPv6 ULA. This does not constitute a complete enterprise denied-network
inventory; production deployment still requires the operator's production,
management, VPN, OT, and other company exclusions. The authorization remains
limited to the target resolved for `asset:winsrv2025-01` and one TCP/22 reachability
probe. Any overlap between that resolved target and a denied entry must fail closed
and must not be handled by adding an exception.

After a completed state run, `harness t3-ready` performs offline composition and
validates that the configured HexStrike URL is exactly `http://127.0.0.1:8888`.
It does not require or contact a running listener. The separate privileged
readiness verifier is responsible for observing the listener immediately before a
real run. `harness t3-scope` prints the canonical, unsigned approval scope and does
not require `HARNESS_APPROVAL_SECRET` or create an approval token.
