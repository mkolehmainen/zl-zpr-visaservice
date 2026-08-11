RELEASE_DIR := build-release
ARCH := $(shell uname -m)
RELEASE_TGZ := "release-linux-$(ARCH).tar.gz"


all: build-rs build-go

clean:
	rm -rf $(RELEASE_DIR)
	cargo clean
	$(MAKE) -C zpr-dashboard $@

check:
	cargo fmt --check
	$(MAKE) -C admin-api-types $@
	$(MAKE) -C vs $@
	$(MAKE) -C libeval $@
	$(MAKE) -C vs-admin $@
	$(MAKE) -C zpt $@

build: build-rs build-go

build-rs:
	cargo build --all-targets

build-go:
	$(MAKE) -C zpr-dashboard build

build-release:
	cargo build -r --all-targets
	$(MAKE) -C zpr-dashboard build

test:
	cargo test
	$(MAKE) -C zpr-dashboard $@

release:
	$(MAKE) clean
	$(MAKE) build-release
	mkdir -p $(RELEASE_DIR)
	./tools/sysinfo > $(RELEASE_DIR)/vs_sysinfo.txt
	cp ./target/release/zpt $(RELEASE_DIR)
	cp ./target/release/vs $(RELEASE_DIR)
	cp ./target/release/vsapikey $(RELEASE_DIR)
	cp ./target/release/vs-admin $(RELEASE_DIR)
	cp ./zpr-dashboard/bin/zpr-dashboard $(RELEASE_DIR)
	cd $(RELEASE_DIR) && tar zcvf ../$(RELEASE_TGZ) .

pregen:
	$(MAKE) -C integration-test/pregen rebuild

sysinfo:
	tools/sysinfo

.PHONY: all clean check build test release pregen sysinfo build-rs build-go build-release

.DEFAULT_GOAL := all
