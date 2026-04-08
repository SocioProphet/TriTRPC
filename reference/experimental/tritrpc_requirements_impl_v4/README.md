# TriTRPC vNext requirements + reference implementation (v0.2)

This sandbox package contains:

- requirements investigation and machine-readable requirement IDs;
- a reference implementation for `Control243`, `S243`, `Handle243`, `Braid243`, and hot-path frames;
- standards-inspired, approved-like, and research assurance profiles;
- explicit boundary manifests, deployment manifests, and hash-chained audit records;
- sample configs, registry data, generated vectors, and tests.

## Layout

- `src/tritrpc_requirements_impl/` — implementation
- `specs/` — requirements docs, crosswalks, and patch plans
- `configs/` — example profiles, boundaries, deployments, and registry
- `artifacts/` — SBOM, provenance, and planning artifacts
- `generated/` — validation outputs, audit chain, vectors, and test report
- `tests/` — pytest coverage

## Quickstart

```bash
cd tritrpc_requirements_impl_v4
PYTHONPATH=src python -m tritrpc_requirements_impl validate configs/fips_classical.yaml
PYTHONPATH=src python -m tritrpc_requirements_impl validate configs/fips_classical.yaml --relaxed
PYTHONPATH=src python -m tritrpc_requirements_impl validate-boundary configs/openssl_fips_boundary.yaml --require-certificate
PYTHONPATH=src python -m tritrpc_requirements_impl validate-deployment configs/standards_inspired.yaml
PYTHONPATH=src python -m tritrpc_requirements_impl emit-vectors generated/sample_vectors_v2.json --null-tag
PYTHONPATH=src python -m tritrpc_requirements_impl emit-audit generated/sample_audit_chain.json --null-tag
PYTHONPATH=src python -m tritrpc_requirements_impl validate-route-policy-vectors ../../../docs/vnext/generated/route_policy_delta_vectors_v1.json ../../../docs/vnext/generated/route_policy_delta_resume_vectors_v1.json
pytest
```

## Transport comparison

Generate the current TriTRPC vs protobuf/thrift comparison artifacts:

```bash
PYTHONPATH=src python -m tritrpc_requirements_impl compare-transports generated/transport_comparison_v3.json --markdown generated/transport_comparison_v3.md
```

## Hybrid / Path-H annex material

- `path_h/README.md` — qutrit / hybrid profile companion package
- `path_h/reference/` — reference encoder
- `path_h/generated/` — canonical fixtures, demo sequence, and notes
- `path_h/parity/` — Go and Rust parity harnesses
