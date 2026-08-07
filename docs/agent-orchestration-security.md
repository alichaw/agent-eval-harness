# Agent orchestration security and evidence

## Architecture and trust boundaries

`core/orchestration` joins the existing capability profiles, asset registry, policy gate,
HexStrike mappings, T3 protected actions, evidence conventions, redaction, and kill
controls. The planner receives only sanitized observations and currently eligible IDs.
Its strict schema rejects target, credential, command, approval claim, scan flag, path,
and every other extra field. Tool output is untrusted data and cannot add capabilities.

`OllamaPlanner` implements the existing `Planner` protocol. It uses `OLLAMA_BASE_URL`
(loopback by default), requires `OLLAMA_MODEL`, and bounds timeout, response bytes,
attempts, and prediction tokens. Its prompt labels observations as hostile data, but the
prompt is defense in depth: strict validation, prohibited-field rejection, current
eligibility, policy, approval, and executor bindings enforce the boundary. Raw model
responses are not included in audit events or safe errors.

The catalog is configuration-time validated against real HexStrike mappings, existing
profiles, registered T3 actions, approval requirements, and known prerequisite evidence
types. Execution still passes through `evaluate_effective_action`; catalog admission is
not a policy bypass. Approval grants bind principal, run, asset, capability, stage,
expiry, and a single-use token record. Existing production T1/T2 and T3 approval/sealing
authorities remain the final execution-boundary controls.

Budgets bound planning steps, tool calls, repeated capabilities, consecutive failures,
duration, and normalized output. The kill switch is checked before planning, policy, and
execution. `HexStrikeAdapter` additionally checks it while polling cancellable jobs. A
stopped run retains prior observations and evidence references.

## Capability and validation status

| Capability group | Route | Approval | Offline | Live |
| --- | --- | --- | --- | --- |
| Service discovery | hardened HexStrike job mapping | policy/profile + execution permit | yes | composed; dedicated-service acceptance pending |
| Web content and safe vulnerability checks | hardened HexStrike job mapping | T2 | yes | pending lab |
| NetBIOS, SMB bounded checks, RDP posture | hardened HexStrike job mapping | T1/T2 | yes | pending lab |
| Authorized access | protected T3 controller | T3-A single-use | yes | existing runtime; unified path pending |
| Windows read-only enumeration | protected T3 controller | T3-B + sealed T3-A | yes | existing runtime; unified path pending |
| Reversible marker proof | fixed T3-C runtime | T3-C + sealed A/B | yes | pending lab |

Offline means deterministic executor output while the real catalog, transitions, policy,
approval scope, budgets, normalization, redaction, and audit path are exercised. It does
not validate HexStrike availability, cancellation over HTTP, Windows behavior, SSH host
keys, credentials, or marker restoration on a live VM.

## Control evidence matrix

| Reference | Requirement/Risk | Implemented control | Code location | Test/evidence | Status | Limitation |
| --- | --- | --- | --- | --- | --- | --- |
| OWASP AISVS C2 | Input validation | Forbid-extra planner and catalog models | `core/orchestration/models.py`, `catalog.py` | `tests/test_orchestration.py` | supports | Not an AISVS assessment |
| OWASP AISVS C5 | Access control | Asset/profile policy resolution and scoped approval | `core/enforcement.py`, `orchestrator.py` | orchestration and safety tests | supports | Principal authentication is deployment-owned |
| OWASP AISVS C7 | Output safety | Credential/IP redaction, size limit, parser uncertainty | `observations.py`, `core/redaction.py` | orchestration/redaction tests | supports | Tool-specific parsing coverage is partial |
| OWASP AISVS C9 | Agentic orchestration | transitions, budgets, approval, shutdown | `transitions.py`, `orchestrator.py` | orchestration tests | partially implements | Live unified cancellation needs lab validation |
| OWASP Agentic Applications Top 10 | Tool misuse / insufficient oversight / cascading failures | allowlisted real bindings, approvals, budgets, kill switch | `capabilities.yaml`, `orchestrator.py` | offline branches and negative tests | supports | Exact identifiers not asserted without local reference PDF |
| OWASP GenAI/LLM Top 10 | Prompt injection, excessive agency, unbounded consumption, improper output handling | strict decision boundary, eligible-ID intersection, budgets, sanitization | `planner.py`, `orchestrator.py`, `observations.py` | mocked negative tests and local fixture runs | supports | Research PoC, not a compliance claim |
| ISO/IEC 42001:2023 | roles, oversight, monitoring, evidence, incident handling, change control | principal/run audit, approvals, evidence IDs, kill state, reviewable catalog | orchestration package and docs | audit events and tests | provides relevant evidence | Certification/compliance not assessed |

No reference PDFs were present in the repository, so this document intentionally avoids
inventing detailed requirement identifiers or exact Agentic Top 10 names. Production
hardening requires authenticated persistent run storage, a durable approval store for the
new orchestration envelope, rate limiting across runs, and lab acceptance of cancellation
and T3 cleanup behavior.

Connectivity, planner execution, fixture execution, and live execution are distinct
claims. `ollama-check` covers endpoint/model connectivity and one schema decision only.
`agent-demo --planner ollama --executor fixture` adds a real planner with deterministic
execution. The live composition exposes only service discovery and records planner,
eligibility, policy, dispatch, job, normalization, evidence, and final state. No live
HexStrike success claim is valid until the dedicated `hexstrike` service returns a real
successful job and evidence trail; a healthy user-mode server alone is insufficient.
