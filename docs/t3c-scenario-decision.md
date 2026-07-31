# T3-C scenario decision required

`lab.synthetic-marker.v1` is currently modeled as a two-asset scenario in the Harness:
the approval binding contains distinct source and destination asset IDs and readiness
requires both resolved targets. The current HexStrike implementation, however, opens
one direct SSH connection to `destination_target` and reads the fixed
`/opt/t3c/proof-marker`; `source_asset_id` is not used by the executor.

That implementation evidence suggests a possible single-target interpretation in which
the Harness/HexStrike host is the executor identity rather than a source lab asset.
Changing to that interpretation would alter the approval fingerprint, configuration
schema, readiness comparison, manifest asset references, tests, and operator
authorization presentation. It therefore requires an explicit human design decision
and migration plan before code changes.

Until that decision is made, the existing two-asset contract remains authoritative and
fails closed when the destination is absent, identical to the source, public, loopback,
not exactly allowlisted, or covered by an operator-denied network. The current
single-approved-asset/public-address environment is intentionally not T3-C ready.

An operator choosing to retain the two-asset design must provide a separately approved
destination asset, distinct private isolated-lab addresses for both assets, complete
company/production/management/VPN denied CIDRs, a predefined marker, and rollback
evidence. No example values authorize execution.

“This research PoC implements selected applicable AISVS controls. It does not claim
complete conformity with AISVS Level 1, Level 2, or Level 3.”
