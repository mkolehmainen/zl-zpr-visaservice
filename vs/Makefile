.PHONY: all build test check

all: build

build:
	cargo build --all-targets

test: build
	cargo test --verbose

check:
	cargo fmt --check && RUSTFLAGS="-D warnings" cargo build --bins

.DEFAULT_GOAL := all
