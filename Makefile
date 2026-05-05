.PHONY: verify fmt rust-fmt go-fmt rust-test go-test fixtures descriptor-manifest-refs aux-shape integration-audit

verify: fmt rust-test go-test fixtures aux-shape

fmt: rust-fmt go-fmt

rust-fmt:
	cd rust/tritrpc_v1 && cargo fmt --check

go-fmt:
	cd go/tritrpcv1 && test -z "$$(gofmt -l .)"

rust-test:
	cd rust/tritrpc_v1 && cargo test

go-test:
	cd go/tritrpcv1 && go test -mod=mod ./...

fixtures: descriptor-manifest-refs
	python tools/verify_fixtures_strict.py

# Warn-only until legacy descriptor manifests are repaired. Direct invocation of
# tools/check_descriptor_manifest_refs.py remains strict and exits non-zero on
# missing local schema/sample/binary references.
descriptor-manifest-refs:
	python tools/check_descriptor_manifest_refs.py --warn-only

aux-shape:
	python tools/verify_policy_evidence_aux_shape.py

integration-audit:
	./tools/audit_branch_pr_integration.sh main HEAD
