# T3-C single-asset decision

The approved contract is `lab.synthetic-marker.v2`: one approved isolated Windows
asset and the registered action `t3c.controlled_impact_proof.v1`. The former
source/destination pairing was removed because the executor used only one target.

The action confirms the fixed marker is absent, creates fixed synthetic content at
the fixed test-only path, verifies its SHA-256 digest, removes it in a mandatory
cleanup path, and verifies absence. Success requires every step. The HTTP caller can
supply only an authorization ID and the canonical action.

This T3-C scenario validates a reversible controlled-impact operation on one approved
isolated asset. It does not test or claim cross-host lateral movement.

This research PoC implements selected applicable AISVS controls. It does not claim
complete conformity with AISVS Level 1, Level 2, or Level 3.
