"""Persistent T3-C pending-action and single-use permit state."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class PendingAction:
    run_id: str
    pending_action_id: str
    authorization_id: str
    asset_id: str
    capability_id: str
    profile_id: str
    protected_scope_digest: str
    requested_at: int
    approval_expires_at: int
    policy_decision_reference: str
    prerequisite_evidence_references: tuple[str, ...]
    attempt_count: int
    current_loop_state: str
    deployment_config_version: str


@dataclass(frozen=True)
class T3CPermit:
    permit_id: str
    pending_action_id: str
    run_id: str
    authorization_id: str
    asset_id: str
    capability_id: str
    profile_id: str
    protected_scope_digest: str
    approved_by: str
    issued_at: int
    expires_at: int
    nonce: str
    max_uses: int = 1


class T3CApprovalStore:
    """SQLite-backed state with process-safe, atomic permit consumption."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS pending_actions ("
                "pending_action_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, "
                "authorization_id TEXT NOT NULL, asset_id TEXT NOT NULL, "
                "capability_id TEXT NOT NULL, profile_id TEXT NOT NULL, "
                "scope_digest TEXT NOT NULL, requested_at INTEGER NOT NULL, "
                "approval_expires_at INTEGER NOT NULL, policy_ref TEXT NOT NULL, "
                "prerequisite_refs TEXT NOT NULL, attempt_count INTEGER NOT NULL, "
                "state TEXT NOT NULL, config_version TEXT NOT NULL);"
                "CREATE UNIQUE INDEX IF NOT EXISTS one_active_pending_per_run_action "
                "ON pending_actions(run_id,pending_action_id);"
                "CREATE TABLE IF NOT EXISTS permits ("
                "permit_id TEXT PRIMARY KEY, pending_action_id TEXT NOT NULL UNIQUE, "
                "claims_json TEXT NOT NULL, nonce_digest TEXT NOT NULL, state TEXT NOT NULL, "
                "issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER);"
            )
        self.path.chmod(0o600)

    @staticmethod
    def action_id(run_id: str, capability_id: str, scope_digest: str) -> str:
        raw = f"{run_id}\0{capability_id}\0{scope_digest}".encode()
        return "pending:" + hashlib.sha256(raw).hexdigest()

    def create_pending(self, pending: PendingAction) -> None:
        if not pending.authorization_id or pending.current_loop_state != "waiting_for_approval":
            raise ValueError("t3c_authorization_required")
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO pending_actions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    pending.pending_action_id,
                    pending.run_id,
                    pending.authorization_id,
                    pending.asset_id,
                    pending.capability_id,
                    pending.profile_id,
                    pending.protected_scope_digest,
                    pending.requested_at,
                    pending.approval_expires_at,
                    pending.policy_decision_reference,
                    json.dumps(pending.prerequisite_evidence_references),
                    pending.attempt_count,
                    pending.current_loop_state,
                    pending.deployment_config_version,
                ),
            )
            db.commit()

    def get_pending(self, pending_action_id: str) -> PendingAction:
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT run_id,pending_action_id,authorization_id,asset_id,capability_id,"
                "profile_id,scope_digest,requested_at,approval_expires_at,policy_ref,"
                "prerequisite_refs,attempt_count,state,config_version "
                "FROM pending_actions WHERE pending_action_id=?",
                (pending_action_id,),
            ).fetchone()
        if row is None:
            raise ValueError("pending_action_not_found")
        values = list(row)
        values[10] = tuple(json.loads(values[10]))
        return PendingAction(*values)

    def approve(
        self,
        pending_action_id: str,
        *,
        approved_by: str,
        ttl_seconds: int = 300,
        now: int | None = None,
    ) -> T3CPermit:
        selected = int(time.time()) if now is None else now
        if not approved_by or not 1 <= ttl_seconds <= 3600:
            raise ValueError("permit_request_invalid")
        pending = self.get_pending(pending_action_id)
        if pending.approval_expires_at <= selected:
            self._set_pending_state(pending_action_id, "approval_expired", "waiting_for_approval")
            raise ValueError("approval_expired")
        nonce = secrets.token_urlsafe(32)
        permit = T3CPermit(
            permit_id="permit:" + secrets.token_hex(16),
            pending_action_id=pending.pending_action_id,
            run_id=pending.run_id,
            authorization_id=pending.authorization_id,
            asset_id=pending.asset_id,
            capability_id=pending.capability_id,
            profile_id=pending.profile_id,
            protected_scope_digest=pending.protected_scope_digest,
            approved_by=approved_by,
            issued_at=selected,
            expires_at=min(selected + ttl_seconds, pending.approval_expires_at),
            nonce=nonce,
        )
        claims = asdict(permit)
        claims.pop("nonce")
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                "UPDATE pending_actions SET state='approved_pending_resume' "
                "WHERE pending_action_id=? AND state='waiting_for_approval'",
                (pending_action_id,),
            )
            if cursor.rowcount != 1:
                db.rollback()
                raise ValueError("pending_action_not_approvable")
            try:
                db.execute(
                    "INSERT INTO permits VALUES (?,?,?,?,'issued',?,?,NULL)",
                    (
                        permit.permit_id,
                        pending_action_id,
                        json.dumps(claims, sort_keys=True),
                        hashlib.sha256(nonce.encode()).hexdigest(),
                        permit.issued_at,
                        permit.expires_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise ValueError("permit_already_exists") from exc
            db.commit()
        return permit

    def consume(
        self, permit: T3CPermit, expected: PendingAction, *, now: int | None = None
    ) -> None:
        selected = int(time.time()) if now is None else now
        claims = asdict(permit)
        nonce = claims.pop("nonce")
        expected_claims = {
            "pending_action_id": expected.pending_action_id,
            "run_id": expected.run_id,
            "authorization_id": expected.authorization_id,
            "asset_id": expected.asset_id,
            "capability_id": expected.capability_id,
            "profile_id": expected.profile_id,
            "protected_scope_digest": expected.protected_scope_digest,
        }
        if any(claims[key] != value for key, value in expected_claims.items()):
            raise ValueError("permit_binding_mismatch")
        if permit.max_uses != 1 or permit.expires_at <= selected:
            raise ValueError("permit_expired_or_invalid")
        with sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE") as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT claims_json,nonce_digest,state,expires_at FROM permits WHERE permit_id=?",
                (permit.permit_id,),
            ).fetchone()
            if (
                row is None
                or row[2] != "issued"
                or int(row[3]) <= selected
                or row[0] != json.dumps(claims, sort_keys=True)
                or row[1] != hashlib.sha256(nonce.encode()).hexdigest()
            ):
                db.rollback()
                raise ValueError("permit_rejected")
            pending_cursor = db.execute(
                "UPDATE pending_actions SET state='running',attempt_count=attempt_count+1 "
                "WHERE pending_action_id=? AND state='approved_pending_resume' "
                "AND run_id=? AND authorization_id=? AND asset_id=? AND capability_id=? "
                "AND profile_id=? AND scope_digest=? AND config_version=? "
                "AND prerequisite_refs=? AND approval_expires_at>?",
                (
                    expected.pending_action_id,
                    expected.run_id,
                    expected.authorization_id,
                    expected.asset_id,
                    expected.capability_id,
                    expected.profile_id,
                    expected.protected_scope_digest,
                    expected.deployment_config_version,
                    json.dumps(expected.prerequisite_evidence_references),
                    selected,
                ),
            )
            permit_cursor = db.execute(
                "UPDATE permits SET state='consumed',consumed_at=? "
                "WHERE permit_id=? AND state='issued'",
                (selected, permit.permit_id),
            )
            if pending_cursor.rowcount != 1 or permit_cursor.rowcount != 1:
                db.rollback()
                raise ValueError("permit_rejected")
            db.commit()

    def finish(self, pending_action_id: str, state: str) -> None:
        if state not in {"succeeded", "failed", "cancelled", "approval_denied"}:
            raise ValueError("pending_terminal_state_invalid")
        self._set_pending_state(pending_action_id, state, "running")

    def deny(self, pending_action_id: str) -> None:
        self._set_pending_state(pending_action_id, "approval_denied", "waiting_for_approval")

    def _set_pending_state(self, pending_action_id: str, state: str, expected: str) -> None:
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as db:
            cursor = db.execute(
                "UPDATE pending_actions SET state=? WHERE pending_action_id=? AND state=?",
                (state, pending_action_id, expected),
            )
            if cursor.rowcount != 1:
                raise ValueError("pending_state_transition_rejected")
