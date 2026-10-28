.PHONY: build-examples build-sabre-loader check-examples e2e

# Vendor sources are tracked in their owning packages. Their existing Cargo
# build scripts validate REVISION and build into Cargo's owned OUT_DIR; there
# are no root third-party submodules to activate in this repository.
build-examples:
	cargo build --locked -p reverie-patching-examples --lib --bins

build-sabre-loader:
	cargo build --locked -p reverie-sabre-strace --lib --bins

check-examples:
	cargo test --locked -p reverie-patching-examples

e2e:
	@./reverie-patching-examples/e2e/run.sh $(E2E_ARGS)
