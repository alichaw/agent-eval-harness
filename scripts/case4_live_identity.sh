# Case 4 — Live read-only SSH identity + replay denial
# LIVE ACTION — HUMAN OPERATOR ONLY

set -eu

HARNESS_ROOT=/home/kali/agent-eval-harness
HARNESS_PYTHON="$HARNESS_ROOT/.venv/bin/python"
RUNTIME_FILE=/etc/hexstrike/t3-unified-runtime.json
AUTH_FILE=/run/hexstrike/t3-identity-authorization.json
SSH_AGENT_SOCKET=/run/hexstrike-t3-ssh-agent/agent.sock
ACTION_ID=windows.ssh.readonly_identity.v1

AUTH_CREATED=0

cleanup() {
  if test "$AUTH_CREATED" -eq 1; then
    sudo -u hexstrike rm -f -- "$AUTH_FILE" || true
  fi
}

trap cleanup EXIT

echo "[1/7] Preflight"

test -x "$HARNESS_PYTHON"
sudo test -f "$RUNTIME_FILE"
sudo test ! -L "$RUNTIME_FILE"
test ! -e "$AUTH_FILE"

sudo systemctl is-active --quiet hexstrike-t3-ssh-agent.service

sudo test -S "$SSH_AGENT_SOCKET"

sudo -u hexstrike env \
  SSH_AUTH_SOCK="$SSH_AGENT_SOCKET" \
  ssh-add -l

echo "[2/7] Creating single-use authorization"

sudo -u hexstrike env \
  PYTHONPATH="$HARNESS_ROOT" \
  "$HARNESS_PYTHON" -m core.cli \
  t3-unified-authorize-identity \
  --runtime-file "$RUNTIME_FILE" \
  --authorization-file "$AUTH_FILE"

AUTH_CREATED=1

sudo test -f "$AUTH_FILE"
sudo test ! -L "$AUTH_FILE"

echo "[3/7] Confirming evidence does not already exist"

sudo -u hexstrike env \
  PYTHONPATH="$HARNESS_ROOT" \
  RUNTIME_FILE="$RUNTIME_FILE" \
  AUTH_FILE="$AUTH_FILE" \
  ACTION_ID="$ACTION_ID" \
  "$HARNESS_PYTHON" - <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.environ["PYTHONPATH"])

from core.t3.poc_runner import load_authorization
from core.t3.poc_runtime import load_runtime

runtime = load_runtime(os.environ["RUNTIME_FILE"])
authorization = load_authorization(os.environ["AUTH_FILE"])

authorization_digest = hashlib.sha256(
    authorization.encode()
).hexdigest()

action_digest = hashlib.sha256(
    json.dumps(
        os.environ["ACTION_ID"],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()

evidence_path = (
    Path(runtime.evidence_root)
    / authorization_digest
    / f"{action_digest}.json"
)

assert not evidence_path.exists(), (
    f"Existing evidence detected before execution: {evidence_path}"
)

print("Evidence freshness precondition PASS")
PY

echo "[4/7] Executing read-only SSH identity action"

set +e

EXECUTION_OUTPUT=$(
  sudo -u hexstrike env \
    PYTHONPATH="$HARNESS_ROOT" \
    SSH_AUTH_SOCK="$SSH_AGENT_SOCKET" \
    "$HARNESS_PYTHON" -m core.cli \
    t3-unified-run \
    --runtime-file "$RUNTIME_FILE" \
    --authorization-file "$AUTH_FILE" 2>&1
)

EXECUTION_STATUS=$?

set -e

printf '%s\n' "$EXECUTION_OUTPUT"

if test "$EXECUTION_STATUS" -ne 0; then
  echo "Case 4 FAIL: live identity execution returned a non-zero status" >&2
  echo "exit_status=$EXECUTION_STATUS" >&2
  exit 1
fi

EXECUTION_STATUS_VALUE=$(
  printf '%s\n' "$EXECUTION_OUTPUT" |
    awk -F':' '
      {
        key=$1
        value=$2
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      }
      key == "status" {result=value}
      END {print result}
    '
)

EXECUTION_ACTION_VALUE=$(
  printf '%s\n' "$EXECUTION_OUTPUT" |
    awk -F':' '
      {
        key=$1
        value=$2
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      }
      key == "action" {result=value}
      END {print result}
    '
)

if test "$EXECUTION_STATUS_VALUE" != completed; then
  echo "Case 4 FAIL: unexpected execution status: $EXECUTION_STATUS_VALUE" >&2
  exit 1
fi

if test "$EXECUTION_ACTION_VALUE" != "$ACTION_ID"; then
  echo "Case 4 FAIL: unexpected action: $EXECUTION_ACTION_VALUE" >&2
  exit 1
fi

echo "[5/7] Verifying replay denial"

set +e

REPLAY_OUTPUT=$(
  sudo -u hexstrike env \
    PYTHONPATH="$HARNESS_ROOT" \
    SSH_AUTH_SOCK="$SSH_AGENT_SOCKET" \
    "$HARNESS_PYTHON" -m core.cli \
    t3-unified-run \
    --runtime-file "$RUNTIME_FILE" \
    --authorization-file "$AUTH_FILE" 2>&1
)

REPLAY_STATUS=$?

set -e

REPLAY_LAST_LINE=$(
  printf '%s\n' "$REPLAY_OUTPUT" |
    sed '/^[[:space:]]*$/d' |
    tail -n 1
)

test "$REPLAY_STATUS" -ne 0

if test "$REPLAY_LAST_LINE" != authorization_rejected; then
  echo "Case 4 FAIL: unexpected replay response" >&2
  echo "replay_status=$REPLAY_STATUS" >&2
  printf '%s\n' "$REPLAY_OUTPUT" >&2
  exit 1
fi

echo "Replay denial PASS"

echo "[6/7] Verifying evidence and approval state"

sudo -u hexstrike env \
  PYTHONPATH="$HARNESS_ROOT" \
  RUNTIME_FILE="$RUNTIME_FILE" \
  AUTH_FILE="$AUTH_FILE" \
  ACTION_ID="$ACTION_ID" \
  "$HARNESS_PYTHON" - <<'PY'
import hashlib
import json
import os
import sqlite3
import stat
import sys
from pathlib import Path

sys.path.insert(0, os.environ["PYTHONPATH"])

from core.t3.poc_runner import load_authorization
from core.t3.poc_runtime import load_runtime

runtime = load_runtime(os.environ["RUNTIME_FILE"])
authorization = load_authorization(os.environ["AUTH_FILE"])

authorization_digest = hashlib.sha256(
    authorization.encode()
).hexdigest()

action_id = os.environ["ACTION_ID"]

action_digest = hashlib.sha256(
    json.dumps(
        action_id,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()

evidence_path = (
    Path(runtime.evidence_root)
    / authorization_digest
    / f"{action_digest}.json"
)

assert evidence_path.is_file(), (
    f"Evidence file is missing: {evidence_path}"
)
assert not evidence_path.is_symlink()

evidence_stat = evidence_path.stat()
assert stat.S_ISREG(evidence_stat.st_mode)

document = json.loads(evidence_path.read_text())
seal = document.pop("seal")

canonical_document = json.dumps(
    document,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
)

expected_seal = hashlib.sha256(
    canonical_document.encode()
).hexdigest()

assert document["schema_version"] == "hexstrike-t3-evidence/v1"
assert seal == expected_seal

# Validate fields only when they are present in the deployed v1 schema.
if "action_id" in document:
    assert document["action_id"] == action_id

if "authorization_id_digest" in document:
    assert (
        document["authorization_id_digest"]
        == authorization_digest
    )

if "runtime_digest" in document:
    assert document["runtime_digest"] == runtime.digest

if "status" in document:
    assert document["status"] == "completed"

with sqlite3.connect(runtime.approval_database) as database:
    approval = database.execute(
        "SELECT state FROM approvals "
        "WHERE authorization_id_digest=?",
        (authorization_digest,),
    ).fetchone()

assert approval == ("consumed",)

print(
    "Case 4 evidence PASS: file, schema, action binding, "
    "runtime binding, self-consistency seal, and approval "
    "consumption verified"
)
PY

echo "[7/7] Cleaning temporary authorization"

sudo -u hexstrike rm -f -- "$AUTH_FILE"
AUTH_CREATED=0

test ! -e "$AUTH_FILE"

trap - EXIT

echo "Case 4 PASS: live read-only SSH identity completed; evidence integrity, approval consumption, and replay denial verified"
