"""Protected local approval state; HexStrike is the sole consumer."""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import stat
import time
from pathlib import Path

from core.t3.poc_registry import ASSET_ID, action

SCHEMA_VERSION = "hexstrike-t3-approvals/v2"


def authorization_digest(authorization_id: str) -> str:
    return hashlib.sha256(authorization_id.encode()).hexdigest()


class ApprovalStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def initialize(self) -> None:
        if self.path.is_symlink():
            raise ValueError("approval_database_invalid")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as database:
            database.executescript(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS approvals ("
                "authorization_id_digest TEXT PRIMARY KEY, action_id TEXT NOT NULL, "
                "asset_id TEXT NOT NULL, runtime_revision TEXT NOT NULL, "
                "runtime_digest TEXT NOT NULL, state TEXT NOT NULL "
                "CHECK(state IN ('pending','consumed','invalidated')), "
                "issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, "
                "consumed_at INTEGER, invalidated_at INTEGER, approving_uid INTEGER NOT NULL, "
                "approval_note_digest TEXT NOT NULL);"
                "CREATE TRIGGER IF NOT EXISTS consumed_approvals_immutable_update "
                "BEFORE UPDATE ON approvals WHEN OLD.state='consumed' "
                "BEGIN SELECT RAISE(ABORT, 'consumed approval immutable'); END;"
                "CREATE TRIGGER IF NOT EXISTS consumed_approvals_immutable_delete "
                "BEFORE DELETE ON approvals WHEN OLD.state='consumed' "
                "BEGIN SELECT RAISE(ABORT, 'consumed approval immutable'); END;"
            )
            database.execute(
                "INSERT OR REPLACE INTO metadata VALUES ('schema_version', ?)",
                (SCHEMA_VERSION,),
            )
        self.path.chmod(0o600)

    def _validate_metadata(self, owner_uid: int | None = None) -> None:
        if self.path.is_symlink():
            raise ValueError("approval_database_invalid")
        try:
            info = self.path.stat()
        except OSError as exc:
            raise ValueError("approval_database_invalid") from exc
        expected = os.geteuid() if owner_uid is None else owner_uid
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("approval_database_invalid")

    def synchronize(self, runtime_digest: str, *, now: int | None = None) -> None:
        self._validate_metadata()
        selected = int(time.time()) if now is None else now
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "UPDATE approvals SET state='invalidated', invalidated_at=? "
                "WHERE state='pending' AND runtime_digest<>?",
                (selected, runtime_digest),
            )
            database.execute(
                "INSERT OR REPLACE INTO metadata VALUES ('active_runtime_digest', ?)",
                (runtime_digest,),
            )
            database.commit()

    def issue(
        self,
        action_id: str,
        asset_id: str,
        runtime_revision: str,
        runtime_digest: str,
        *,
        ttl_seconds: int = 300,
        approving_uid: int,
        approval_note: str = "",
        now: int | None = None,
    ) -> str:
        if not 1 <= ttl_seconds <= 86_400:
            raise ValueError("approval_ttl_invalid")
        action(action_id)
        self._validate_metadata()
        if asset_id != ASSET_ID:
            raise ValueError("approval_asset_invalid")
        selected = int(time.time()) if now is None else now
        action(action_id)
        self.synchronize(runtime_digest, now=selected)
        authorization_id = secrets.token_urlsafe(32)
        with sqlite3.connect(self.path) as database:
            database.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, NULL, NULL, ?, ?)",
                (
                    authorization_digest(authorization_id),
                    action_id,
                    asset_id,
                    runtime_revision,
                    runtime_digest,
                    selected,
                    selected + ttl_seconds,
                    approving_uid,
                    hashlib.sha256(approval_note.encode()).hexdigest(),
                ),
            )
        return authorization_id

    def consume(
        self,
        authorization_id: str,
        action_id: str,
        asset_id: str,
        runtime_revision: str,
        runtime_digest: str,
        *,
        now: int | None = None,
    ) -> None:
        """HexStrike-only atomic transition; callers must not use this from the runner."""
        self._validate_metadata()
        selected = int(time.time()) if now is None else now
        with sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE") as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "UPDATE approvals SET state='invalidated', invalidated_at=? "
                "WHERE state='pending' AND runtime_digest<>?",
                (selected, runtime_digest),
            )
            cursor = database.execute(
                "UPDATE approvals SET state='consumed', consumed_at=? "
                "WHERE authorization_id_digest=? AND state='pending' AND action_id=? "
                "AND asset_id=? AND runtime_revision=? AND runtime_digest=? "
                "AND issued_at<=? AND expires_at>?",
                (
                    selected,
                    authorization_digest(authorization_id),
                    action_id,
                    asset_id,
                    runtime_revision,
                    runtime_digest,
                    selected,
                    selected,
                ),
            )
            if cursor.rowcount != 1:
                database.rollback()
                raise ValueError("authorization_rejected")
            database.commit()

    def inspect_pending(
        self,
        authorization_id: str,
        asset_id: str,
        runtime_revision: str,
        runtime_digest: str,
        *,
        owner_uid: int | None = None,
        now: int | None = None,
    ) -> str:
        """Read-only operator precheck; HexStrike remains the sole consumer."""
        try:
            self._validate_metadata(owner_uid)
        except ValueError:
            raise ValueError("authorization_rejected") from None
        selected_now = int(time.time()) if now is None else now
        with sqlite3.connect(self.path) as database:
            row = database.execute(
                "SELECT action_id,issued_at,expires_at,approval_note_digest "
                "FROM approvals WHERE authorization_id_digest=? AND state='pending' "
                "AND asset_id=? AND runtime_revision=? AND runtime_digest=?",
                (
                    authorization_digest(authorization_id),
                    asset_id,
                    runtime_revision,
                    runtime_digest,
                ),
            ).fetchone()
        if row is None:
            raise ValueError("authorization_rejected")
        selected_action = action(str(row[0]))
        empty_note = hashlib.sha256(b"").hexdigest()
        if (
            int(row[1]) > selected_now - selected_action.approval_delay_seconds
            or int(row[2]) <= selected_now
            or (selected_action.justification_required and row[3] == empty_note)
        ):
            raise ValueError("authorization_rejected")
        return selected_action.action_id
