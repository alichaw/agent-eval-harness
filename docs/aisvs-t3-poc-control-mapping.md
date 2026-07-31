# AISVS 1.0 mapping for the T3 research PoC

Source: OWASP AISVS 1.0 stable Markdown, principally
[`C9 Orchestration & Agentic Security`](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md)
and
[`C12 Monitoring, Logging & Anomaly Detection`](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C12-Monitoring-and-Logging.md).
The operator-provided PDF path was unavailable in this environment, so the stable
official Markdown was used instead. Requirement meanings below are concise
paraphrases, not replacements for the standard.

| AISVS requirement | Concise official meaning | Project implementation | Verification evidence | Status |
|---|---|---|---|---|
| v1.0-C9.1.1 | Enforce per-tool resource and execution-time limits. | Fixed T3-A/B/C call, session, timeout, and output limits. | `tests/test_t3_access.py`, `tests/test_t3_enumeration.py`, `tests/test_t3c_impact.py` | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.2.1 | Block high-impact actions until explicit human approval is verified. | Stage-specific short-lived approval is consumed before T3-A/B/C execution. | `tests/test_t3_controller.py`, `tests/test_t3b_security_regressions.py`, `tests/test_t3c_impact.py` | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.2.2 | Present complete canonical action parameters for approval. | `t3-approve` prints asset, resolved target identity, stage, fixed actions, runtime binding, and profile. | `tests/test_t3_cli.py` | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.2.8 | Cryptographically bind approvals to action, requester/context, and a unique nonce. | HMAC action/context binding and atomic nonce consumption exist; requester identity and downstream T3-C correlation are incomplete in PoC. | Approval/replay tests; T3-C design review | SKIPPED_BY_POC_PROFILE |
| v1.0-C9.2.9 | Isolate approval signing credentials from the agent runtime. | Required by `hardened`; explicitly deferred by `poc`. | `tests/test_t3_assurance.py` | SKIPPED_BY_POC_PROFILE |
| v1.0-C9.3.1 | Execute tools with least privilege or equivalent isolation. | Fixed read-only actions and low-privilege lab account are implemented; dedicated executor identity is deferred. | Registry tests and operator lab account review | IMPLEMENTED_NOT_LAB_VERIFIED |
| v1.0-C9.3.2 | Validate tool outputs against schemas. | SSH/22 state producer and T3-A/B/C adapters require exact structured response fields and states. | `tests/test_t3_ssh_reachability_state.py`, endpoint tests | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.3.3 | Tool declarations identify privileges, resource limits, and output validation. | Profiles declare fixed tools, parameters, limits, and evidence requirements. | `profiles.yaml`; profile and registry tests | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.3.4 | Runtime enforces declared privileges, limits, and validation. | Canonical registries, fingerprints, controller gates, and bounded executors enforce declarations. | T3 security regression suites | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.5.1 | Fine-grained runtime policy restricts tools and parameter values. | Default deny, asset allowlist, deny precedence, canonical action IDs, and no caller target/port/command fields. | Policy, CLI injection, state-producer, and endpoint tests | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.5.2 | Propagate an integrity-protected, scope-limited authorization context downstream. | Hardened signed permits implement this for T3-A/B; PoC loopback paths defer it and T3-C has no correlated downstream token. | Assurance profile tests | SKIPPED_BY_POC_PROFILE |
| v1.0-C9.5.3 | Enforce access decisions in deterministic application/policy logic, not the model. | Harness policy and canonical registry resolve all executable state. | Policy and proposal rejection tests | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.5.4 | Keep runtime secrets and credentials outside model-visible context and tool parameters. | Agent sees references only; credential resolution occurs after approval; state probe has no credential surface. | Redaction, credential sentinel, and state-producer tests | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.6.1 | Provide a manual kill switch that immediately stops agent operation. | File-backed kill switch is checked before execution and during T3-A/B. | Kill-switch regression tests | IMPLEMENTED_AND_VERIFIED |
| v1.0-C9.6.2 | Expired or unsatisfied approvals block pending actions. | Approval TTL and missing/expired token rejection. | Approval authority and T3 stage tests | IMPLEMENTED_AND_VERIFIED |
| v1.0-C12.1.2 | Log safety-filter and policy decisions for audit and forensics. | Manifest, structured trace events, result, policy rules, and artifact seals for T3-A/B. | Replay/artifact validation tests | IMPLEMENTED_AND_VERIFIED |
| v1.0-C12.4.2 | Audit security-critical proactive actions with approver, time, parameters, and decision. | Action scope, timestamps, safe fingerprints, decisions, and results are logged; approver identity is not modeled. | Artifact inspection tests | GAP |
| v1.0-C12.4.3 | Log kill-switch activation and overrides. | Activation is traced; override-command workflow is not implemented. | Kill-switch trace tests | GAP |
| Project default-deny boundary (supports v1.0-C9.5.1/C9.5.3) | Unknown tools, assets, stages, parameters, or failures must not authorize action. | Policy defaults to deny; operator denied CIDRs are mandatory for T3 state production; unexpected validation errors fail closed. | Policy, denied-target, malformed-output, and unknown-asset tests | IMPLEMENTED_AND_VERIFIED |
| Full AISVS Level 1/2/3 conformity | Verify every applicable requirement at the selected level. | This focused PoC maps selected controls only. | This mapping and explicit non-claim fields | OUT_OF_SCOPE |

“This research PoC implements selected applicable AISVS controls. It does not claim
complete conformity with AISVS Level 1, Level 2, or Level 3.”
