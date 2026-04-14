# Semantic-proof transport failure separation v0.1

This note keeps transport failures and semantic-proof failures explicitly distinct in the fixture surface.

## Transport-facing failure classes
- deadline_exceeded
- peer_unreachable
- route_resolution_failed
- envelope_verification_failed
- retry_exhausted

## Semantic-proof failure classes
- E_PROOF_SCHEMA_INVALID
- E_PROOF_VERSION_UNSUPPORTED
- E_PROOF_TREE_ALG_UNSUPPORTED
- E_PROOF_HASH_ALG_UNSUPPORTED
- E_PROOF_LEAF_HASH_MISMATCH
- E_PROOF_AUDIT_PATH_INVALID
- E_PROOF_ROOT_MISMATCH
- E_PROOF_BOUNDARY_INVALID
- E_PROOF_KEY_ORDER_INVALID
- E_PROOF_CONSISTENCY_INVALID
- E_PROOF_DIFF_REF_UNRESOLVED
- E_PROOF_SNAPSHOT_STATE_INVALID

## Rule
A transport failure must not be emitted as if it were a semantic-proof failure, and a semantic-proof verifier failure must not be hidden behind a generic transport error.

## Why
This preserves the repo-role split:
- TriTRPC owns transport carriage, retry, and envelope behavior.
- standards-storage owns canonical proof identifiers and verifier code vocabulary.
- agentplane consumes proof-bearing results and runtime receipts.
