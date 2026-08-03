# Mesh orchestrator (the fabric that consumes every stage)

`reference/mesh_orchestrator.py` runs a Work-Unit end to end by composing the stages into one
pipeline, so no stage is an orphan:

```
admit (node_admission)
  -> register + liveness (mesh_runtime)
  -> schedule (mesh_scheduler)
  -> dispatch (mesh_runtime)
  -> collect (mesh_scheduler)
  -> settle (mesh_coordinator -> suite_gate + proof_envelope + attestation_verifier)
```

Because the orchestrator imports `node_admission`, `mesh_scheduler`, `mesh_runtime`, and
`mesh_coordinator` (which itself enforces `suite_gate`, `proof_envelope`, and `attestation_verifier`),
a green `tools/verify_mesh_orchestrator.py` proves **every mesh reference module is consumed by the
runtime** — the fabric, not a set of self-testing patches.

Fail-closed throughout: a reputation that is not admitted never enters the trusted set, so it can
never be scheduled, dispatched to, or credited; a suite-N workload never settles on a below-N node;
too few admitted nodes refuses to schedule. FIPS-clean downstream; does not touch the wire. The only
remaining runtime is the transport that moves the bytes (QUIC/libp2p), which is delegated.
