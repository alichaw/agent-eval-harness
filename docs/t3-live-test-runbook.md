# Human-executed T3-A → T3-B → T3-C live-test runbook

Do not run this procedure without current written authorization. Codex did not execute
these commands. If any value, target, authorization scope, host key, or expected state
does not match, stop. Do not bypass the validation.

## Pre-test checklist

Confirm the authorization window, isolated Windows Server asset, snapshot/recovery
checkpoint, Kali-only TCP/22 allowlist, low-privilege account, pinned host key, fixed
test-only marker path, execution limits, writable evidence directory, kill switch,
listener shutdown procedure, and manual rollback procedure. No second target is
required. Confirm the marker contains no business or personal data and is absent.

## Protected configuration and listener

Human action: back up existing files, edit secrets interactively without command-line
values, install protected copies, inspect the unit, start and verify the listener.

The HexStrike documentation-only templates are:

- `/home/kali/hexstrike-ai/t3-poc-runtime.example.json`;
- `/home/kali/hexstrike-ai/t3a-credentials.example.json`; and
- `/home/kali/hexstrike-ai/t3c-runtime.example.json`.

### Dedicated identity-agent deployment phases

The repository-defined agent unit is `hexstrike-t3-ssh-agent.service`. Its fixed
socket and provisioning-marker locations are defined by
`config/t3-identity-agent-runtime.json`; operators must not replace them with
`SSH_AUTH_SOCK` from an interactive shell, a path under `/tmp`, or a private-key
path. The unit runs `ssh-agent` in the foreground as `hexstrike`, creates its private
runtime directory through systemd, and removes the socket and provisioning marker
when the unit stops.

Perform these later deployment steps manually; they are not part of offline testing:

1. Inspect the repository unit and JSON contract. Confirm the unit uses `User` and
   `Group` `hexstrike`, `RuntimeDirectoryMode=0700`, `UMask=0077`, foreground agent
   mode, and the exact fixed socket from the contract.
2. Install the agent unit and the selected HexStrike service unit as protected
   systemd configuration, then run `systemctl daemon-reload`.
3. Start only `hexstrike-t3-ssh-agent.service`. Confirm systemd reports it active and
   that the fixed path exists, is a Unix-domain socket owned and accessible by
   `hexstrike`, and has no world access. Do not list identities during this check.
4. Provision the approved low-privilege identity using a separate protected operator
   procedure. Only after that procedure succeeds, create the fixed provisioning
   marker as `hexstrike` with mode `0600`. Socket availability alone does not prove
   identity provisioning.
5. Run the identity-agent readiness checks. Stop for any missing unit, inactive
   service, absent or wrong-type socket, ownership/access mismatch, missing
   provisioning marker, or configuration path mismatch.
6. Start `hexstrike-t3-poc.service` only after the identity-agent checks pass, then run
   the complete PoC readiness verifier. Stopping HexStrike also stops the PartOf agent
   unit and removes its runtime state.

The corresponding manual systemd preparation sequence is:

```bash
cd /home/kali/agent-eval-harness
systemd-analyze verify config/systemd/hexstrike-t3-ssh-agent.service \
  config/systemd/hexstrike-t3-poc.service
sudo install -o root -g root -m 0644 \
  config/systemd/hexstrike-t3-ssh-agent.service \
  /etc/systemd/system/hexstrike-t3-ssh-agent.service
sudo install -o root -g root -m 0644 \
  config/systemd/hexstrike-t3-poc.service \
  /etc/systemd/system/hexstrike-t3-poc.service
sudo systemctl daemon-reload
systemctl cat hexstrike-t3-ssh-agent.service
systemctl cat hexstrike-t3-poc.service
sudo systemctl start hexstrike-t3-ssh-agent.service
systemctl is-active hexstrike-t3-ssh-agent.service
sudo -u hexstrike test -S /run/hexstrike-t3-ssh-agent/agent.sock
```

At this point the agent may be empty. Complete the separately approved protected
identity-provisioning procedure without placing key material in command arguments or
logs. Only after that procedure confirms success, create the runtime-scoped completion
marker and verify its metadata:

```bash
sudo -u hexstrike install -m 0600 /dev/null \
  /run/hexstrike-t3-ssh-agent/identity-provisioned
sudo stat -c '%U:%G %a %F' \
  /run/hexstrike-t3-ssh-agent/agent.sock \
  /run/hexstrike-t3-ssh-agent/identity-provisioned
```

Do not create the marker merely because the socket exists. Stop the agent unit to
remove the runtime directory, socket, and marker if provisioning fails. Do not start
HexStrike until all agent metadata and provisioning checks pass.

The protected credential map and T3-C runtime must both use the exact repository
socket contract. There is no fallback to a private-key reference or another assurance
profile.

Prepare protected replacements outside the repositories. Do not edit a template in
place or place protected values in shell arguments. Every installed HexStrike JSON file
below must be `root:hexstrike 0640`.

Establish and validate the containing directory and file metadata without changing
file contents:

```bash
cd /home/kali/agent-eval-harness
sudo scripts/setup_t3_poc_config_permissions.sh --apply
sudo scripts/setup_t3_poc_config_permissions.sh --check
```

For a foreground diagnostic start as the dedicated non-root account, use:

```bash
sudo -u hexstrike env -i HOME=/var/lib/hexstrike \
  HEXSTRIKE_ASSURANCE_PROFILE=poc HEXSTRIKE_HOST=127.0.0.1 HEXSTRIKE_PORT=8888 \
  HEXSTRIKE_T3_REACHABILITY_CONFIG=/etc/hexstrike/t3-reachability.json \
  /home/kali/hexstrike-ai/hexstrike-env/bin/python3 \
  /home/kali/hexstrike-ai/hexstrike_server.py
```

Verify the fixed HTTP boundary:

```bash
curl --fail-with-body --silent --show-error \
  -H 'Content-Type: application/json' \
  --data '{"action_id":"t3a.ssh22_reachability.v1","asset_id":"asset:winsrv2025-01"}' \
  http://127.0.0.1:8888/api/v1/t3/ssh-reachability
```

Then produce the canonical Harness state once:

```bash
cd /home/kali/agent-eval-harness
.venv/bin/harness t3-state --asset-id asset:winsrv2025-01 \
  --assets config/local/assets.yaml --profiles profiles.yaml \
  --policy config/local/policy.yaml \
  --runs-root runs --kill-switch-file config/local/KILL --confirm-lab-probe
```

The five files form one contract:

- `asset_id` is exactly `asset:winsrv2025-01` everywhere it appears;
- the target in `t3-reachability.json`, its `/32` in `job-targets.json`, the target
  used to derive `t3-poc-runtime.json.target_binding`, and the T3-C/Harness targets
  identify the same approved asset;
- `port` is exactly integer `22`, and the target-binding digest covers the fixed asset,
  target, and port with the repository's `target_binding` algorithm;
- `assurance_profile` is explicitly `poc` in both PoC runtime files and the Harness PoC
  runtime; no profile fallback is permitted;
- `credential:ssh-winsrv2025-01`, the credential-map key, and Harness credential
  references identify the same approved credential;
- username and identity-agent references in the credential map and T3-C runtime refer
  to the same low-privilege identity; they are protected values, not HTTP parameters;
- the pinned host key in the common runtime and the pinned known-hosts source used by
  T3-C represent the same independently verified host identity; the referenced
  known-hosts file must also be `root:hexstrike 0640`;
- T3-A is one session with its fixed three actions; T3-B is five commands, one session,
  15 seconds per command and 60 seconds total; T3-C is six calls and 60 seconds total;
- T3-C scenario, marker path, content digest, cleanup, rollback verification, and
  isolated-lab assertion exactly match the fixed loader contract.

Back up existing files without printing their contents, then install all five:

```bash
for name in t3-reachability.json t3-poc-runtime.json job-targets.json t3a-credentials.json t3c-runtime.json; do
  if sudo test -f "/etc/hexstrike/$name"; then
    sudo cp -a "/etc/hexstrike/$name" "/etc/hexstrike/$name.bak.<RUN_ID>"
  fi
done
sudo install -o root -g hexstrike -m 0640 <PREPARED_T3_REACHABILITY_CONFIG> /etc/hexstrike/t3-reachability.json
sudo install -o root -g hexstrike -m 0640 <PREPARED_T3_POC_RUNTIME_CONFIG> /etc/hexstrike/t3-poc-runtime.json
sudo install -o root -g hexstrike -m 0640 <PREPARED_JOB_TARGETS_CONFIG> /etc/hexstrike/job-targets.json
sudo install -o root -g hexstrike -m 0640 <PREPARED_T3A_CREDENTIALS_CONFIG> /etc/hexstrike/t3a-credentials.json
sudo install -o root -g hexstrike -m 0640 <PREPARED_T3C_RUNTIME_CONFIG> /etc/hexstrike/t3c-runtime.json
sudo install -o root -g root -m 0600 <PREPARED_HARNESS_T3C_CONFIG> <PROTECTED_HARNESS_T3C_CONFIG>
sudo stat -c '%U:%G %a %n' /etc/hexstrike/t3-reachability.json /etc/hexstrike/t3-poc-runtime.json /etc/hexstrike/job-targets.json /etc/hexstrike/t3a-credentials.json /etc/hexstrike/t3c-runtime.json
systemctl cat hexstrike-t3-poc.service
sudo systemctl start hexstrike-t3-poc.service
systemctl status --no-pager hexstrike-t3-poc.service
journalctl -u hexstrike-t3-poc.service --since '-5 minutes' --no-pager
ss -ltnp | rg '127\.0\.0\.1:8888'
cd /home/kali/agent-eval-harness
sudo .venv/bin/python scripts/verify_t3_operator_readiness.py \
  --assurance-profile poc
```

Expected: `assurance_profile: poc`, protected PoC configuration checks, fixed asset and
limit checks, loopback-only listener, invalid-authorization rejection on all three PoC
endpoints, replay and kill-switch checks, and `overall_pass: true`. Signed permits,
approval-key isolation, hardened routes, and UID firewall enforcement must each report
`status: SKIPPED_BY_PROFILE`; they must not be reported as PoC failures. Retain the
sanitized JSON output. Stop for public binding, exposed protected values, a failed
common control, a hardened check reported as passed under PoC, or any profile mismatch.
Kill switch and shutdown commands are:

```bash
sudo install -o hexstrike -g hexstrike -m 0600 /dev/null /run/hexstrike/KILL
sudo systemctl stop hexstrike-t3-poc.service
```

## T3-A

Human action: review readiness/scope, issue one short-lived approval, execute once,
inspect artifacts, then attempt only the repository-supported offline replay check.

```bash
cd /home/kali/agent-eval-harness
.venv/bin/harness t3-ready --asset-id <APPROVED_ASSET_ID> --profile-id t3-authorized-access-bounded --runtime-config <PROTECTED_T3_RUNTIME_CONFIG> --assets <PROTECTED_ASSETS_FILE> --profiles profiles.yaml --policy policy.yaml --investigation-state <T3A_INVESTIGATION_STATE> --approval-spent-dir <APPROVAL_SPENT_DIR>
.venv/bin/harness t3-scope --asset-id <APPROVED_ASSET_ID> --profile-id t3-authorized-access-bounded --runtime-config <PROTECTED_T3_RUNTIME_CONFIG> --assets <PROTECTED_ASSETS_FILE> --profiles profiles.yaml --policy policy.yaml --investigation-state <T3A_INVESTIGATION_STATE> --approval-spent-dir <APPROVAL_SPENT_DIR>
.venv/bin/harness t3-approve --asset-id <APPROVED_ASSET_ID> --profile-id t3-authorized-access-bounded --runtime-config <PROTECTED_T3_RUNTIME_CONFIG> --assets <PROTECTED_ASSETS_FILE> --profiles profiles.yaml --policy policy.yaml --investigation-state <T3A_INVESTIGATION_STATE> --approval-spent-dir <APPROVAL_SPENT_DIR> --ttl-seconds 300 --output <T3A_APPROVAL_TOKEN_FILE>
T3_LAB_EXECUTION_ENABLED=true .venv/bin/harness t3-run --asset-id <APPROVED_ASSET_ID> --profile-id t3-authorized-access-bounded --runtime-config <PROTECTED_T3_RUNTIME_CONFIG> --assets <PROTECTED_ASSETS_FILE> --profiles profiles.yaml --policy policy.yaml --investigation-state <T3A_INVESTIGATION_STATE> --approval-spent-dir <APPROVAL_SPENT_DIR> --approval-token-file <T3A_APPROVAL_TOKEN_FILE> --runs-root <RUNS_ROOT> --kill-switch-file <KILL_SWITCH_PATH>
```

Expected: readiness displays the one asset and fixed action/limits; execution prints a
run directory and completed status. Retain readiness, scope, approval metadata, run ID,
manifest, trace, result, cleanup/limit evidence, and replay-rejection evidence. Pass
only if the fixed action, approved asset, limits, cleanup, sanitization, and single-use
approval all verify. On failure, stop before T3-B.

## T3-B

Human action: use the successful original T3-A run as the prerequisite and issue a new
stage-specific approval.

```bash
cd /home/kali/agent-eval-harness
.venv/bin/harness t3-ready --asset-id <APPROVED_ASSET_ID> --profile-id windows-host-enumeration-readonly --runtime-config <PROTECTED_T3_RUNTIME_CONFIG> --assets <PROTECTED_ASSETS_FILE> --profiles profiles.yaml --policy policy.yaml --prerequisite-run-dir <T3A_RUN_DIR> --approval-spent-dir <APPROVAL_SPENT_DIR>
.venv/bin/harness t3-scope --asset-id <APPROVED_ASSET_ID> --profile-id windows-host-enumeration-readonly --runtime-config <PROTECTED_T3_RUNTIME_CONFIG> --assets <PROTECTED_ASSETS_FILE> --profiles profiles.yaml --policy policy.yaml --prerequisite-run-dir <T3A_RUN_DIR> --approval-spent-dir <APPROVAL_SPENT_DIR>
.venv/bin/harness t3-approve --asset-id <APPROVED_ASSET_ID> --profile-id windows-host-enumeration-readonly --runtime-config <PROTECTED_T3_RUNTIME_CONFIG> --assets <PROTECTED_ASSETS_FILE> --profiles profiles.yaml --policy policy.yaml --prerequisite-run-dir <T3A_RUN_DIR> --approval-spent-dir <APPROVAL_SPENT_DIR> --ttl-seconds 300 --output <T3B_APPROVAL_TOKEN_FILE>
T3_LAB_EXECUTION_ENABLED=true .venv/bin/harness t3-run --asset-id <APPROVED_ASSET_ID> --profile-id windows-host-enumeration-readonly --runtime-config <PROTECTED_T3_RUNTIME_CONFIG> --assets <PROTECTED_ASSETS_FILE> --profiles profiles.yaml --policy policy.yaml --prerequisite-run-dir <T3A_RUN_DIR> --approval-spent-dir <APPROVAL_SPENT_DIR> --approval-token-file <T3B_APPROVAL_TOKEN_FILE> --runs-root <RUNS_ROOT> --kill-switch-file <KILL_SWITCH_PATH>
```

Retain prerequisite reference, approval metadata, run ID, evidence-binding fields,
manifest, trace, result, replay and cross-stage rejection evidence. Pass only if the
sealed T3-A prerequisite, fixed registry, limits, evidence binding, sanitization, and
single-use approval verify. On failure, stop before T3-C.

## T3-C

Human action: verify readiness against both successful sealed runs, issue a separate
approval, execute exactly once, and inspect the complete lifecycle.

```bash
cd /home/kali/agent-eval-harness
.venv/bin/python scripts/verify_t3c_readiness.py --runtime-config <PROTECTED_HARNESS_T3C_CONFIG> --hexstrike-config /etc/hexstrike/t3c-runtime.json --t3a-result <T3A_RUN_DIR>/result.json --t3b-result <T3B_RUN_DIR>/result.json --approval-spent-dir <APPROVAL_SPENT_DIR> --approval-token-file <T3C_APPROVAL_TOKEN_FILE> --kill-switch-file <KILL_SWITCH_PATH>
.venv/bin/python scripts/issue_t3c_approval.py --runtime-config <PROTECTED_HARNESS_T3C_CONFIG> --t3a-result <T3A_RUN_DIR>/result.json --t3b-result <T3B_RUN_DIR>/result.json --approval-token-file <T3C_APPROVAL_TOKEN_FILE> --approval-spent-dir <APPROVAL_SPENT_DIR> --ttl-seconds 300
.venv/bin/python scripts/run_t3c_acceptance.py --confirm-isolated-lab --runtime-config <PROTECTED_HARNESS_T3C_CONFIG> --t3a-result <T3A_RUN_DIR>/result.json --t3b-result <T3B_RUN_DIR>/result.json --approval-token-file <T3C_APPROVAL_TOKEN_FILE> --approval-spent-dir <APPROVAL_SPENT_DIR> --kill-switch-file <KILL_SWITCH_PATH>
```

The HTTP body remains exactly `authorization_id` plus `canonical_action`. Expected
result: `succeeded` and true initial-absence, creation, proof, cleanup, and rollback
fields. Retain both prerequisite references, T3-B binding, approval metadata, run ID,
manifest, trace, result, cleanup/rollback evidence, independent authorized absence
confirmation, and replay rejection. Creation alone is failure.

## Failure, recovery, and evidence

For mismatch, expiry, unexpected identity/traffic/connector use, pre-existing marker,
proof mismatch, timeout, or limit breach: stop and preserve evidence. For cleanup or
rollback failure, do not rerun; activate the kill switch, stop the listener, preserve
failure artifacts, inspect only the approved fixed marker path using the approved
operator procedure, remove only that marker if authorized, verify absence, record
manual recovery, restore the snapshot if needed, and require new authorization.

Scan without printing matching values:

```bash
rg -l -i 'password|private[_ -]?key|agent[_ -]?socket|authorization[_ -]?secret|token|ssh-ed25519|credential' <RUNS_ROOT>/<RUN_ID>
git -C /home/kali/agent-eval-harness diff --check
git -C /home/kali/hexstrike-ai diff --check
tar --create --gzip --file <SANITIZED_ACCEPTANCE_PACKAGE>.tar.gz --directory <RUNS_ROOT> <T3A_RUN_ID> <T3B_RUN_ID> <T3C_RUN_ID>
```

Review every file named by the scan before packaging. Do not package approval-token
files, runtime configuration, credentials, keys, host keys, or agent-socket data.

This T3-C scenario validates a reversible controlled-impact operation on one approved
isolated asset. It does not test or claim cross-host lateral movement.

This research PoC implements selected applicable AISVS controls. It does not claim
complete conformity with AISVS Level 1, Level 2, or Level 3.
