# Suite-separation conformance (v4 §15.1)

v4 §15.1 requires a fixture class for **approved/non-approved suite separation**. This is it — a
single conformance artifact proving the suite selector is *enforced*, not merely declared.

`fixtures/conformance/suite_separation_matrix.json` records the monotone gate matrix (a workload of
`requiredSuite r` runs on a profile of `suite p` **iff p ≥ r**) and anchors the canonical per-suite
CryptoProfile / FederationCryptoProfile examples. `tools/verify_suite_separation.py`:

1. **recomputes** the gate matrix with `reference/suite_gate.py` and compares it to the recorded
   fixture (recompute-don't-trust) — every cell must match `p ≥ r`;
2. confirms each anchored profile resolves to its claimed suite;
3. runs the CryptoProfile and FederationCryptoProfile validators and requires both green — their
   approved suites accepted, their under-assured / non-FIPS profiles refused.

Together these show separation end to end: an under-assured profile is refused at the profile gate,
and a higher-suite workload is refused on a lower-suite profile at the placement gate. FIPS: no
primitive (comparison + validator composition); does not touch the wire.
