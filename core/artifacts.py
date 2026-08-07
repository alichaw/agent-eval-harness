"""Authenticated final seals for immutable run artifact sets."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.safety import ApprovalAuthority

SEAL_FILENAME = "artifact-seal.json"
SEAL_VERSION = "hmac-sha256-v1"


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class ArtifactSealAuthority:
    """HMAC authority whose secret never enters the artifact directory."""

    key: bytes
    key_id: str

    @classmethod
    def from_approval_authority(cls, authority: ApprovalAuthority) -> ArtifactSealAuthority:
        key = hmac.new(
            authority.secret,
            b"agent-eval-harness/artifact-seal/v1",
            hashlib.sha256,
        ).digest()
        return cls(key, hashlib.sha256(key).hexdigest()[:16])

    @classmethod
    def for_test(cls, secret: bytes, key_id: str = "offline-test-key") -> ArtifactSealAuthority:
        if len(secret) < 32:
            raise ValueError("artifact seal secret must contain at least 32 bytes")
        return cls(secret, key_id)

    def _document(self, root: Path) -> dict[str, Any]:
        manifest_raw = (root / "manifest.json").read_bytes()
        result_raw = (root / "result.json").read_bytes()
        trace_raw = (root / "trace.jsonl").read_bytes()
        manifest = json.loads(manifest_raw)
        result = json.loads(result_raw)
        last_line = trace_raw.splitlines()[-1]
        final_event = json.loads(last_line)
        return {
            "seal_version": SEAL_VERSION,
            "key_id": self.key_id,
            "run_id": manifest.get("run_id"),
            "final_trace_digest": final_event.get("event_digest"),
            "trace_digest": _digest(trace_raw),
            "manifest_digest": _digest(manifest_raw),
            "result_digest": _digest(result_raw),
            "execution_mode": manifest.get("execution_mode", "lab_real"),
            "stage": result.get("stage") or manifest.get("stage"),
            "capability": result.get("profile_id"),
        }

    def seal(self, run_dir: str | Path) -> None:
        root = Path(run_dir)
        document = self._document(root)
        signature = hmac.new(self.key, _canonical(document), hashlib.sha256).hexdigest()
        (root / SEAL_FILENAME).write_text(
            json.dumps({"document": document, "signature": signature}, indent=2),
            encoding="utf-8",
        )

    def verify(self, run_dir: str | Path) -> str:
        root = Path(run_dir)
        try:
            sealed = json.loads((root / SEAL_FILENAME).read_text(encoding="utf-8"))
            document = sealed["document"]
            signature = sealed["signature"]
            if not isinstance(document, dict) or not isinstance(signature, str):
                return "malformed_artifact_seal"
            if (
                document.get("seal_version") != SEAL_VERSION
                or document.get("key_id") != self.key_id
            ):
                return "artifact_seal_identity_mismatch"
            expected = hmac.new(self.key, _canonical(document), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return "invalid_artifact_seal"
            if document != self._document(root):
                return "artifact_seal_content_mismatch"
        except FileNotFoundError:
            return "missing_artifact_seal"
        except (OSError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
            return "malformed_artifact_seal"
        return ""
