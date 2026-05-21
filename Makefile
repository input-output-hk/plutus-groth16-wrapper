.PHONY: build build-rust build-go test test-rust test-go

build: build-rust build-go

build-rust:
	cargo build --manifest-path zkwrap-rs/Cargo.toml

build-go:
	cd zkwrap-gnark && go build ./...

test: test-rust test-go

test-rust:
	cargo test --manifest-path zkwrap-rs/Cargo.toml

test-go:
	cd zkwrap-gnark && go test ./...
