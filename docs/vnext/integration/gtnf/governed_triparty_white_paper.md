# Governed Triparty Netting Fabric
## A technical architecture for multi-ledger settlement, proof-carrying coordination, and ASI-ecosystem integration

Version 1.0-rc1  
Date: 2026-04-05

## Abstract

The governed triparty netting fabric (GTNF) is a release-boundary architecture for heterogeneous settlement, proof-carrying coordination, authority routing, and governed export. The central claim is that the right interoperability primitive is not a bridge, not a registry, and not a coordination standard taken in isolation. The right primitive is a governed triparty clearing cell that can cancel circulatory gross flow, preserve proof and provenance, separate evidence from permission, and support release, refund, suppression, or export according to policy rather than mere confidence.

GTNF is designed to operate across public chains, rollups, bank ledgers, custodial systems, registry systems, institutional data planes, identity systems, and disclosure surfaces. In all of those environments, the same failure recurs: local records may be individually correct while global truth remains partially hidden, delayed, compartmentalized, or policy-constrained. GTNF addresses that failure by coupling value flow, authority, capability, proof, and export control into one governed release calculus.

The execution primitive is a filled triparty simplex \(\Delta^2=[A,B,C]\), where A, B, and C are any three boundary-bearing systems capable of holding balances, claims, commitments, or permissions. A triparty cell is the smallest object that can extinguish circulatory gross flow internally before residual imbalance is sent to the edges. The governance primitive is a nested admissibility lattice:

\[
\Gamma_{\mathrm{evid}}
\supseteq
\Gamma_{\mathrm{admit}}
\supseteq
\Gamma_{\mathrm{release}}
\supseteq
\Gamma_{\mathrm{export}}.
\]

The release law is:

\[
\lambda_{\mathrm{release}}^{(k)} = \eta(H_t,k)\,\rho_t^{(k)}\,p_t^{(k)}\,\lambda_{\mathrm{evid}}^{(k)}
\]

where \(p_t\) is the policy gate, \(\rho_t\) is the proof/finality gate, and \(\eta(H_t,k)\) is the macro-health dampener. GTNF therefore treats evidence, policy, proof, and systemic health as independent components of release rather than collapsing them into one confidence score.

## 1. Problem statement

Bridges, registries, and coordination standards each solve part of the problem, but none of them by themselves define a governed release constitution. ERC-7683 defines structured cross-chain orders and legs. ERC-8001 defines a minimal multi-party coordination primitive with explicit states. Across describes a three-layer intent architecture and a three-phase lifecycle of initiation, fill, and settlement. IBC packet semantics make proof verification, acknowledgement, and timeout discipline explicit. W3C VC 2.0, Data Integrity, and BBS support portable proof carriage and selective disclosure. BODS models immutable, source-attributed statements. FATF guidance emphasizes multi-pronged access to adequate, accurate, and up-to-date information. Taken together, those are fragments of one architecture, but the governance boundary remains underspecified.

GTNF fills that gap by making one rule explicit: evidence proposes, policy disposes, proof preserves the result, and export is always stricter than local validity.

## 2. Core object model

A local GTNF record is typed as:

\[
z=(y,q,s,\chi,v,\mu,\alpha,\pi)
\]

where:
- \(y\): typed event, claim, intent leg, packet, credential, or ledger action
- \(q\): context or prime vector
- \(s\): scope or trust domain
- \(\chi\): truth class
- \(v\): validity / finality interval
- \(\mu\): rule bundle for merge, contradiction, suppression, witness, and export
- \(\alpha\): action-rights bundle
- \(\pi\): proof artifact or proof pointer

Truth classes are operational, not decorative:
- **PROVEN** — ledger-verified state, light-client verified commitments, packet proofs
- **ATTESTED** — authenticated participant acceptances, institutional assertions, role credentials
- **INFERRED** — model outputs, route forecasts, hidden-state reconstruction, estimated capacities
- **REPUTED** — external risk context and intelligence

The constitutional rule is that belief must not masquerade as proof, and role must not masquerade as control.

## 3. Lifecycle

The GTNF lifecycle is:

\[
Observed \to Proposed \to Ready / ReviewRequired / Blocked \to Escrowed \to Filled \to Verified \to Released
\]

with side exits to:

\[
Cancelled, Expired, Refunded, Revoked, Disputed, Unmerged, Exported.
\]

This lifecycle separates observation, coordination, fill, verification, release, and export. The architecture therefore remains reversible when contradiction evidence, witness revocation, timeout, or policy discovery invalidates an earlier stronger state.

## 4. Policy and export gates

A candidate relation score \(\sigma_{ij}\) is evidence, not permission. Merge or admission is:

\[
M_{ij}=
\mathbf 1[\sigma_{ij}\ge \tau]
\mathbf 1[P(q_i,q_j,s_i,s_j,\chi_i,\chi_j,W_{ij},V_{ij})=1]
\]

where \(W_{ij}\) is witness state and \(V_{ij}\) is contradiction-veto state.

Export is a stricter gate:

\[
X_{ij}=M_{ij}\,\mathbf 1[E(\nu_i,\nu_j,s_i\to s_j)=1].
\]

This is the heart of the architecture: local admissibility is not equal to downstream exportability.

## 5. Protocol economics and contract surfaces

GTNF should not introduce a competing settlement token inside the current ASI ecosystem. The monetary base is the existing ASI token surface, operationally represented today as FET (ASI) on live rails. Above that monetary base sit bonded security, local reserves, capability rights, and non-monetary proof artifacts.

The main contract / module surfaces are:
- **NettingCell** — local triparty execution object
- **EscrowVault** — monetary lock layer
- **BondVault** — slashable collateral layer
- **CapabilityRegistry** — rights issuance / delegation / revocation
- **ProofRegistry** — commitments, replay handles, revocation references
- **ReserveManager** — local reserve bucket and draw policy
- **FeeRouter** — fee routing across burn, validators, treasury, staking, and reserves

The fee law is:

\[
F_k = \phi_k \lambda_{\mathrm{release}}^{(k)} = B_k + V_k + T_k + M_k + R_k
\]

where the split coefficients may be governed by the macro-health controller.

## 6. Trust model

The trusted computing base is intentionally narrow. GTNF does not assume ordinary execution actors are trustworthy. The minimal trust base is:
1. finalized base-ledger state,
2. sound proof verifiers,
3. the identified policy bundle that governed the decision,
4. at least one honest challenger where optimistic verification is used.

Adversary classes include replay attackers, stale-proof attackers, false-authority attackers, scope-violation attackers, withholding actors, bundle-fraud actors, and reserve-drain actors.

The timing law is:

\[
\Delta=(\Delta_{ready},\Delta_{fill},\Delta_{verify},\Delta_{dispute},\Delta_{revoke},\Delta_{export})
\]

with ordering:

\[
\Delta_{ready}\le \Delta_{fill}\le \Delta_{verify}\le \Delta_{dispute}\le \Delta_{revoke}\le \Delta_{export}.
\]

## 7. Interfaces and proof bundles

The logical artifacts are:
- `IntentBundle`
- `AcceptanceBundle`
- `EscrowBundle`
- `FillBundle`
- `VerificationBundle`
- `ChallengeBundle`
- `RevocationBundle`
- `ExportBundle`

The rule is: only a `VerificationBundle` can authorize release, and only if proof class, freshness, replay safety, contradiction checks, and challenge clearance all pass.

## 8. ASI / SingularityNET integration

Current SingularityNET rails already host the money leg and much of the authorization leg of the design:
- ASI(FET) monetary base
- Multi-Party Escrow
- payment channels
- daemon-side per-call authorization and validation
- delayed provider claiming

GTNF does not need to replace those rails to be useful. The correct posture is:
- **agree** with the live rails where they already work,
- **wrap** them with stronger proof and policy boundaries,
- **extend** them with witness, contradiction, reserve, and export logic,
- **defer** any substrate rewrite until validation shows it is needed.

## 9. Validation substrate

The validation substrate now includes a deterministic adversarial reference model and scorecard. Current canonical hardening rules include:
- release materiality floor: \(\epsilon_{release}=1.0\)
- memo carrier size boundary: `MAX_MEMO_BYTES = 2048`
- canonical branch ordering:
  - carrier size / parse
  - callback sender authorization
  - replay / nonce
  - timeout
  - proof-handle integrity
  - witness freshness
  - proof / finality
  - materiality
  - contradiction
  - export

Canonical negative classes now include:
- `NoReleasableCycle`
- `BlockedProof`
- `BlockedStaleWitness`
- `RejectedMalformedProof`
- `RejectedOversizedMemo`
- `RejectedMalformedCallbackSender`
- `ExportDeniedContradictoryWitnessLocalReleasePreserved`

The current deterministic scorecard tracks FRR, RRR, TRI, CVP, EDC, WFR, PHR, MBR, CBR, XWR, and capital-efficiency/compression metrics.

## 10. Deployment modes

### 10.1 Current ASI(FET) + MPE mode

Near-term deployment can sit on the current SingularityNET rails using ASI(FET), MPE, payment channels, and daemon-side service authorization. GTNF then acts as the governed release shell above the existing monetary substrate.

### 10.2 Cosmos / IBC mode

The first external adapter target is IBC Classic over ICS-20 with callbacks and `memo.gtnf`. The first locked implementation target is the current v10 release line, with logical bundles kept v2-friendly while the carrier remains Classic for the first executable path.

## 11. Worked conclusion

GTNF is not another bridge, registry, or credential wallet. It is a governed release constitution that can sit above those substrates and decide when evidence becomes admissible, when admissibility becomes releasable, and when local validity becomes exportable.

That is the useful boundary. That is the thing missing from most current interoperability stacks.
