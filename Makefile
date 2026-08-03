.PHONY: verify fmt rust-fmt go-fmt rust-test go-test fixtures descriptor-manifest-refs aux-shape avro-lom-diagrams build-forge integration-audit

verify: fmt rust-test go-test fixtures aux-shape avro-lom-diagrams build-forge

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

descriptor-manifest-refs:
	python tools/check_descriptor_manifest_refs.py

aux-shape:
	python tools/verify_policy_evidence_aux_shape.py

avro-lom-diagrams:
	python tools/check_avro_lom_diagrams.py

build-forge:
	python tools/verify_build_forge_state_machine.py

integration-audit:
	./tools/audit_branch_pr_integration.sh main HEAD
