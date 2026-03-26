# TriTRPC Requirements and Reference Implementation v0.2

This package now supports two orthogonal dimensions:

- wire/crypto semantics: research, FIPS-classical, CNSA2-ready;
- assurance target: research, standards-inspired, approved-like.

## Implemented modules

- `codec.py` — Control243, TritPack243, TLEB3, S243, Handle243
- `frames.py` — canonical unary, stream, and beacon frames
- `naming.py` — braided IDs and Braid243
- `policy.py` — profile semantics and validation pedigree checks
- `boundary.py` — explicit cryptographic boundary manifests
- `deployment.py` — standards-inspired / approved-like deployment validation
- `audit.py` — hash-chained audit logs
- `registry.py` — route + identity handle registry
- `padic.py` — optional 3-adic refinement helpers

## Main remediation over v0.1

v0.1 answered “what should the wire look like?”

v0.2 answers:

- what should be required in a hardened commercial deployment;
- which parts of government-grade standards are worth copying even without formal certification;
- how to tell apart semantic correctness from certificate pedigree.

## Validation surfaces

- profile validation — algorithm and transport semantics;
- boundary validation — runtime, self-tests, SBOM, provenance, fail-closed posture;
- deployment validation — process controls, logging, transition planning, AI secure-development alignment.

## Generated evidence

The package emits:

- canonical sample vectors;
- sample audit chain;
- boundary validation outputs;
- deployment validation outputs;
- pytest report.
