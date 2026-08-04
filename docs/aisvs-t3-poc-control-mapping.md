# AISVS 1.0 reference mapping for the narrow T3 research PoC

This is a conservative implementation mapping, not an AISVS compliance claim.
The reference is the supplied local mapping plus OWASP AISVS 1.0 C5, C9, and C12.

| Control reference | Selected PoC behavior | Status |
|---|---|---|
| C5.2.1 | Exact asset/action allowlists and default denial | Partially demonstrated offline |
| C5.2.5 | Harness request/policy logic is separated from HexStrike execution | Partially demonstrated offline |
| C9.1.1/C9.1.2 | Fixed attempts, command count, timeouts, and output bounds | Demonstrated with fake transport |
| C9.2.1 | Every action requires a short-lived single-use approval | Demonstrated offline; human acceptance pending |
| C9.2.3/C9.2.4 | Reachability and read-only identity are classified non-mutating; no marker action | Demonstrated by registry and command tests |
| C9.3.2 | Exact request/result/evidence/runtime schemas | Demonstrated offline |
| C9.3.3/C9.3.4 | Two fixed tools with enforced privileges and limits | Demonstrated offline |
| C9.3.7 | Target and credential reference resolve only from protected asset registry/runtime | Demonstrated offline |
| C9.5.1/C9.5.3 | Runtime application logic authorizes canonical actions and fixed parameters | Demonstrated offline |
| C9.5.4 | Credential material is absent from request/result/evidence/model context | Partially demonstrated offline |
| C9.5.6 | Action, asset, revision, digest, TTL, state, and kill switch are rechecked at execution | Demonstrated offline |
| C9.6.1/C9.6.2 | File kill switch blocks new work; unsatisfied approvals fail closed | Demonstrated offline |
| C12.1.1/C12.1.2 | Structured sealed action and denial records contain normalized decisions | Demonstrated offline |
| C12.4.2/C12.4.3 | Approval digest/decision and kill-switch denial are auditable | Partially demonstrated offline |

Residual gaps include C9.2.8 cryptographic approval binding, C9.2.9 approval-key
isolation, C9.3.1 OS sandbox isolation, C9.4 service/orchestrator identity proof,
C9.6.3 out-of-band shutdown delivery, externally protected tamper-resistant audit
storage, and any live adapter beyond this exact Windows SSH slice. Complete AISVS
Level 2 or Level 3 verification is outside scope.
