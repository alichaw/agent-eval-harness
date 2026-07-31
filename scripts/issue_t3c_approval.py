"""Issue a fresh approval bound to protected T3-C configuration and T3-B evidence."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from core.artifacts import ArtifactSealAuthority
from core.safety import ApprovalAuthority
from core.t3.impact import ACTION_ID, T3CConfig, binding, validate_readiness


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-config", required=True)
    parser.add_argument("--t3b-result", required=True)
    parser.add_argument("--approval-token-file", required=True)
    parser.add_argument("--approval-spent-dir", required=True)
    parser.add_argument("--ttl-seconds", type=int, default=300)
    args = parser.parse_args()
    secret = os.environ.get("HARNESS_APPROVAL_SECRET", "")
    if len(secret.encode()) < 32:
        raise SystemExit("HARNESS_APPROVAL_SECRET must contain at least 32 bytes")
    config = T3CConfig.model_validate_json(Path(args.runtime_config).read_text(encoding="utf-8"))
    prerequisite = Path(args.t3b_result)
    authority = ApprovalAuthority(secret.encode(), args.approval_spent_dir)
    digest = validate_readiness(
        config,
        prerequisite,
        seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
    )
    fingerprint = binding(config, digest)
    token = authority.issue(
        config.source_asset_id,
        ACTION_ID,
        fingerprint,
        ttl_seconds=args.ttl_seconds,
        credential_id=config.credential_ref,
        action_fingerprint=fingerprint,
    )
    output = Path(args.approval_token_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    print(f"fresh T3-C approval written: {output}")
    print(f"safe authorization fingerprint: {fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
