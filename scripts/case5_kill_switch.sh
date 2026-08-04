#!/usr/bin/env bash

# Case 5 — Kill-switch denial and audit verification
# LIVE ACTION — HUMAN OPERATOR ONLY

set -Eeuo pipefail

HARNESS_ROOT=/home/kali/agent-eval-harness
HARNESS_PYTHON="$HARNESS_ROOT/.venv/bin/python"
RUNTIME_FILE=/etc/hexstrike/t3-unified-runtime.json
AUTH_FILE=/run/hexstrike/t3-kill-denial-authorization.json
KILL_FILE=/run/hexstrike/KILL
ACTION_ID=windows.ssh.readonly_identity.v1

AUTH_CREATED=0
KILL_CREATED=0

cleanup() {
    if test "$KILL_CREATED" -eq 1; then
        sudo rm -f -- "$KILL_FILE" || true
    fi

    if test "$AUTH_CREATED" -eq 1; then
        sudo -u hexstrike rm -f -- "$AUTH_FILE" || true
    fi
}

trap cleanup EXIT

echo "[1/6] Preflight"

test -x "$HARNESS_PYTHON" || {
    echo "Case 5 FAIL: Harness Python is unavailable" >&2
    exit 1
}

sudo test -f "$RUNTIME_FILE" || {
    echo "Case 5 FAIL: runtime file is missing" >&2
    exit 1
}

sudo test ! -L "$RUNTIME_FILE" || {
    echo "Case 5 FAIL: runtime file must not be a symlink" >&2
    exit 1
}

test ! -e "$AUTH_FILE" || {
    echo "Case 5 FAIL: authorization file already exists: $AUTH_FILE" >&2
    exit 1
}

test ! -e "$KILL_FILE" || {
    echo "Case 5 FAIL: kill-switch file already exists: $KILL_FILE" >&2
    exit 1
}

echo "Preflight PASS"

echo "[2/6] Creating single-use authorization"

sudo -u hexstrike env \
    PYTHONPATH="$HARNESS_ROOT" \
    "$HARNESS_PYTHON" -m core.cli \
    t3-unified-authorize-identity \
    --runtime-file "$RUNTIME_FILE" \
    --authorization-file "$AUTH_FILE"

AUTH_CREATED=1

sudo test -f "$AUTH_FILE" || {
    echo "Case 5 FAIL: authorization file was not created" >&2
    exit 1
}

sudo test ! -L "$AUTH_FILE" || {
    echo "Case 5 FAIL: authorization file is a symlink" >&2
    exit 1
}

echo "[3/6] Engaging kill switch"

sudo install \
    -o hexstrike \
    -g hexstrike \
    -m 0600 \
    /dev/null \
    "$KILL_FILE"

KILL_CREATED=1

sudo test -f "$KILL_FILE" || {
    echo "Case 5 FAIL: kill-switch file was not created" >&2
    exit 1
}

sudo test ! -L "$KILL_FILE" || {
    echo "Case 5 FAIL: kill-switch file is a symlink" >&2
    exit 1
}

echo "Kill switch engaged"

echo "[4/6] Verifying execution denial"

set +e

DENIAL_OUTPUT=$(
    sudo -u hexstrike env \
        PYTHONPATH="$HARNESS_ROOT" \
        "$HARNESS_PYTHON" -m core.cli \
        t3-unified-run \
        --runtime-file "$RUNTIME_FILE" \
        --authorization-file "$AUTH_FILE" 2>&1
)

DENIAL_STATUS=$?

set -e

printf '%s\n' "$DENIAL_OUTPUT"

if test "$DENIAL_STATUS" -eq 0; then
    echo "Case 5 FAIL: execution unexpectedly returned status 0" >&2
    exit 1
fi

DENIAL_LAST_LINE=$(
    printf '%s\n' "$DENIAL_OUTPUT" |
        sed '/^[[:space:]]*$/d' |
        tail -n 1
)

if test "$DENIAL_LAST_LINE" != "kill_switch_engaged"; then
    echo "Case 5 FAIL: unexpected denial response" >&2
    echo "exit_status=$DENIAL_STATUS" >&2
    echo "last_line=$DENIAL_LAST_LINE" >&2
    exit 1
fi

echo "Kill-switch denial PASS"

echo "[5/6] Verifying pending approval and sealed audit event"

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
raw_authorization = load_authorization(os.environ["AUTH_FILE"])
action_id = os.environ["ACTION_ID"]

authorization_digest = hashlib.sha256(
    raw_authorization.encode()
).hexdigest()

with sqlite3.connect(runtime.approval_database) as database:
    approval = database.execute(
        "SELECT state FROM approvals "
        "WHERE authorization_id_digest=?",
        (authorization_digest,),
    ).fetchone()

assert approval == ("pending",), (
    "Expected approval state ('pending',), "
    f"received {approval!r}"
)

audit_root = Path(runtime.evidence_root) / "audit"

assert audit_root.is_dir(), (
    f"Audit directory is missing: {audit_root}"
)

matches = []

for path in audit_root.glob("*.json"):
    if path.is_symlink() or not path.is_file():
        continue

    path_stat = path.stat()
    assert stat.S_ISREG(path_stat.st_mode), (
        f"Audit entry is not a regular file: {path}"
    )

    try:
        candidate = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        continue

    if (
        candidate.get("authorization_id_digest")
        == authorization_digest
        and candidate.get("action_id") == action_id
        and candidate.get("runtime_digest") == runtime.digest
        and candidate.get("policy_decision")
        == "kill_switch_denied"
    ):
        matches.append((path, candidate))

assert len(matches) == 1, (
    "Expected exactly one matching kill-switch audit event, "
    f"found {len(matches)}"
)

audit_path, audit_document = matches[0]

assert audit_document.get("schema_version"), (
    "Audit event is missing schema_version"
)

seal = audit_document.get("seal")

assert isinstance(seal, str) and seal, (
    "Audit event is missing a valid seal"
)

unsealed_document = dict(audit_document)
unsealed_document.pop("seal")

canonical_document = json.dumps(
    unsealed_document,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
)

expected_seal = hashlib.sha256(
    canonical_document.encode()
).hexdigest()

assert seal == expected_seal, (
    "Audit event seal verification failed"
)

print(f"Audit file: {audit_path}")
print(
    "Case 5 audit PASS: authorization remains pending; "
    "specific kill-switch denial is bound and sealed"
)
PY

echo "[6/6] Cleaning temporary authorization and kill switch"

sudo rm -f -- "$KILL_FILE"
KILL_CREATED=0

sudo -u hexstrike rm -f -- "$AUTH_FILE"
AUTH_CREATED=0

test ! -e "$KILL_FILE" || {
    echo "Case 5 FAIL: kill-switch cleanup failed" >&2
    exit 1
}

test ! -e "$AUTH_FILE" || {
    echo "Case 5 FAIL: authorization cleanup failed" >&2
    exit 1
}

trap - EXIT

echo "Case 5 PASS: kill-switch denial audited; approval remained pending; temporary files removed"
