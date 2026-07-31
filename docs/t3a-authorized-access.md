# T3-A authorized credential access

T3-A has two explicit bounded-access intents. They share the same fixed command,
transport, approval, kill-switch, cleanup, and redaction controls, but have
different prerequisite semantics.

`t3-access-bounded` is vulnerability-driven `initial_access`. It requires a
confirmed finding classified as `confirmed_vulnerability` or `exploitable`.
An open SSH port or approved credential never satisfies that gate.

`t3-authorized-access-bounded` is `authorized_access`. It represents an
operator-approved, pre-provisioned low-privilege account on a registered
Windows OpenSSH lab host. It requires no vulnerability finding and rejects
finding references. It instead requires recent, complete, non-truncated,
error-free, same-asset evidence that structurally identifies reachable/open
TCP port 22 as SSH or OpenSSH.

The separate profile is mandatory; credential presence does not infer access
intent. The authorized-access proposal exposes only the asset and profile; its
three command IDs are fixed by the canonical registry, and the CLI rejects
`--command-id` for this profile. The executable, target, port, username,
credential reference, private key, pinned host key, SSH options, timeouts, and
session policy remain operator-controlled.

Authorized-access readiness additionally verifies:

- proposal, investigation, runtime, and registry asset identity;
- an isolated-lab host using `windows_openssh` on SSH port 22;
- exact equality between registered and private-runtime credential references;
- a valid pinned Ed25519 host key;
- the approval-required profile and default-deny target/capability/stage policy;
- only `current_identity`, `host_identity`, and `privilege_context`;
- SSH evidence no older than 24 hours and not dated in the future.

The policy target allowlist and exact asset/profile/stage binding are the
repository's current scope-authorization record. The repository does not yet
model a separately signed, expiring written-authorization document. Operators
must continue to retain real written authorization outside the repository as
described in `authorizations/README.md`.

Readiness is offline: it does not read the private key, resolve a credential, or
open a transport. Approval remains short-lived and single-use. Execution remains
disabled unless `T3_LAB_EXECUTION_ENABLED` is exactly `true`.
