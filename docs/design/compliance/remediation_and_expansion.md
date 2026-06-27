# TriTRPC Requirements Remediation and Expansion v0.2

Date: 2026-03-11

## Goal shift

The target is no longer formal federal deployment approval. The target is to **mimic the strongest parts of government-grade standards and operational discipline** without pretending to hold a certification.

That leads to a two-axis model:

1. **Wire/crypto suite** — research, FIPS-classical semantics, CNSA2-ready semantics.
2. **Assurance target** — research, standards-inspired, approved-like.

This matters because a system can emulate government-grade discipline (algorithm choice, transport preference, logging, supply-chain visibility, crypto agility, fail-closed behavior, canonical vectors) even when it does not bind to an active validated module.

## What was remediated

### 1) Profile semantics vs validation pedigree

Previously, the reference code treated approved-family semantics and active module pedigree as one thing.

Now the package separates them:

- `validate_profile(..., require_validated_module=True)` models approved-like deployments.
- `validate_profile(..., require_validated_module=False)` models standards-inspired deployments.
- deployment manifests bind the assurance target to the strictness of module requirements.

### 2) Explicit cryptographic boundary manifest

Added `boundary.py` and YAML manifests.

The boundary manifest now captures:

- module name / runtime binding;
- optional certificate pedigree;
- approved-mode intent;
- selected algorithms and transports;
- tested operational environment pinning;
- self-tests and fail-closed behavior;
- entropy-source documentation;
- SBOM and provenance artifact references;
- key-separation and zeroization notes.

This is the strongest practical lesson from FIPS/CMVP that still helps outside government procurement: **state the boundary clearly, pin it, and fail closed.**

### 3) Standards-inspired deployment manifest

Added `deployment.py` and deployment YAML manifests.

A deployment manifest now validates:

- assurance target;
- canonical wire lock;
- golden vectors;
- negative tests;
- audit logging;
- transition plan;
- key-management plan;
- logging plan;
- C-SCRM plan;
- SSDF alignment;
- AI-SSDF alignment for AI systems;
- separate research build;
- provenance attestation;
- cryptographic inventory.

### 4) Hash-chained audit records

Added `audit.py`.

The package now emits and verifies SHA-384/SHA-512 chained audit records so we can mimic the spirit of government logging and accountability: frame events, suite choices, and policy decisions become tamper-evident records.

### 5) Relaxed no-certificate path

Added `relaxed_no_cert_boundary.yaml` and `standards_inspired_no_cert.yaml`.

This demonstrates the policy split directly:

- standards-inspired mode accepts a boundary without a certificate number;
- approved-like mode requires the certificate pedigree.

That is the honest commercial posture: emulate the discipline, avoid false claims.

## What remains intentionally unremediated

1. Binding to a real validated runtime inside this sandbox.
2. Patching the upstream Go/Rust repo directly.
3. Final topic23 registry and real braided naming taxonomy.
4. Production PKI policy/OID/DN mapping.
5. Live transport bindings for TLS/IPsec/SSH.

## New files

### Code

- `src/tritrpc_requirements_impl/boundary.py`
- `src/tritrpc_requirements_impl/deployment.py`
- `src/tritrpc_requirements_impl/audit.py`

### Configs

- `configs/openssl_fips_boundary.yaml`
- `configs/awslc_fips_boundary.yaml`
- `configs/relaxed_no_cert_boundary.yaml`
- `configs/standards_inspired.yaml`
- `configs/approved_like.yaml`
- `configs/cnsa2_standards_inspired.yaml`
- `configs/standards_inspired_no_cert.yaml`

### Artifacts

- `artifacts/sbom.spdx.json`
- `artifacts/build_provenance.json`
- `artifacts/algorithm_transition_plan.md`
- `artifacts/key_management_plan.md`
- `artifacts/logging_plan.md`
- `artifacts/cscrm_plan.md`

### Generated outputs

- `generated/sample_vectors_v2.json`
- `generated/sample_audit_chain.json`
- `generated/openssl_boundary_validation.json`
- `generated/awslc_boundary_validation.json`
- `generated/standards_inspired_validation.json`
- `generated/approved_like_validation.json`
- `generated/standards_inspired_no_cert_validation.json`
- `generated/test_report_v2.txt`

## Design stance

The package is now more useful because it distinguishes three things cleanly:

- **what the wire says**;
- **what the crypto semantics are**;
- **how much standards discipline the deployment wants to emulate**.

That separation is the right long-term architecture for TriTRPC.
