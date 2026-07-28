"""core/credentials.py — named credential storage for T3 tools.

Credentials are NEVER embedded in case files, CLI arguments, or trace/log
output (see policy.yaml's t3_low/t3_high credential-handling note). A case
or approval names a credential_id only; the secret itself is read from an
individually-permissioned file at the moment of use and never round-trips
through anything that gets persisted.
"""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from pathlib import Path


class CredentialError(ValueError):
    pass


@dataclass(frozen=True)
class Credential:
    """A named credential set, scoped to specific assets.

    repr/str deliberately never include `secret` -- an accidental print(),
    log call, or f-string of a Credential must not leak it.
    """

    credential_id: str
    username: str
    secret: str
    allowed_asset_ids: tuple[str, ...]

    def __repr__(self) -> str:
        return (
            f"Credential(credential_id={self.credential_id!r}, "
            f"username={self.username!r}, secret=<redacted>, "
            f"allowed_asset_ids={self.allowed_asset_ids!r})"
        )

    __str__ = __repr__

    def authorizes(self, asset_id: str) -> bool:
        return asset_id in self.allowed_asset_ids


class CredentialStore:
    """Loads named credentials from a directory of 0600 JSON files.

    Layout: <root>/<credential_id>.json, each:
        {"username": "...", "secret": "...", "allowed_asset_ids": ["asset:foo"]}

    Fails closed: a missing file, wrong permissions, or malformed/incomplete
    entry all raise CredentialError rather than returning something partial.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def load(self, credential_id: str) -> Credential:
        if (
            not credential_id
            or credential_id in {".", ".."}
            or "/" in credential_id
            or "\\" in credential_id
        ):
            raise CredentialError(f"invalid credential id: {credential_id!r}")

        path = self.root / f"{credential_id}.json"
        try:
            info = path.stat()
        except OSError as exc:
            raise CredentialError(f"unknown credential: {credential_id}") from exc

        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o077:
            raise CredentialError(f"credential file must have mode 0600: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CredentialError(f"cannot read credential {credential_id}: {exc}") from exc

        if not isinstance(data, dict):
            raise CredentialError(f"credential {credential_id} must be a JSON object")

        username = data.get("username", "")
        secret = data.get("secret", "")
        allowed = data.get("allowed_asset_ids", [])
        if not username or not isinstance(username, str):
            raise CredentialError(f"credential {credential_id} missing username")
        if not secret or not isinstance(secret, str):
            raise CredentialError(f"credential {credential_id} missing secret")
        if (
            not isinstance(allowed, list)
            or not allowed
            or not all(isinstance(a, str) for a in allowed)
        ):
            raise CredentialError(
                f"credential {credential_id} must list at least one allowed_asset_ids entry"
            )

        return Credential(
            credential_id=credential_id,
            username=username,
            secret=secret,
            allowed_asset_ids=tuple(allowed),
        )
