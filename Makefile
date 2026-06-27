.PHONY: verify fmt rust-fmt go-fmt rust-test go-test fixtures

verify: fmt rust-test go-test fixtures

fmt: rust-fmt go-fmt

rust-fmt:
	cd rust/tritrpc && cargo fmt --check

go-fmt:
	cd go/tritrpc && test -z "$$(gofmt -l .)"

rust-test:
	cd rust/tritrpc && cargo test

go-test:
	cd go/tritrpc && go test ./...

fixtures:
	python tools/verify_fixtures_strict.py
