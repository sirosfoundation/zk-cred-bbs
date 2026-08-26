# zk-cred-bbs Makefile — binding generation for the four consumers.
#
# Mirrors zk-cred-vega's and zk-cred-longfellow's Makefiles (same org, same
# UniFFI/cross-compile shape). This crate has one more target than they do:
# a browser build, because wallet-frontend is meant to run this
# implementation rather than a parallel TypeScript one.
#
# Targets:
#   make bindings-kotlin   — generate Kotlin bindings from the host library
#   make bindings-swift    — generate Swift bindings from the host library
#   make go-cabi           — build the plain C-ABI cdylib/staticlib for cgo,
#                            staged alongside the hand-written C header
#   make go-smoketest      — build go-cabi and exercise the C ABI from Go
#   make wasm              — build the browser/npm package via wasm-pack
#   make check-go-header   — fail if the hand-written C header has drifted
#   make check-bindings    — CI helper: fail if generated bindings are stale
#   make clean             — remove build artifacts

CRATE_NAME := zk_cred_bbs
LIB_NAME   := lib$(CRATE_NAME)
UNAME_S    := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  HOST_LIB_EXT := dylib
else
  HOST_LIB_EXT := so
endif

BUILD_DIR    := target
BINDINGS_DIR := bindings
KOTLIN_DIR   := $(BINDINGS_DIR)/kotlin
SWIFT_DIR    := $(BINDINGS_DIR)/swift
GO_CABI_DIR  := $(BUILD_DIR)/go-cabi
WASM_DIR     := pkg

# getrandom 0.4 needs an explicit backend on wasm32-unknown-unknown; without
# this the build fails at link time with a missing __getrandom symbol.
WASM_RUSTFLAGS := --cfg getrandom_backend="wasm_js"

.PHONY: all bindings-kotlin bindings-swift uniffi-lib go-cabi go-smoketest wasm \
        check-go-header check-bindings clean FORCE

all: bindings-kotlin bindings-swift

# ── UniFFI (Kotlin / Swift) ─────────────────────────────────────────

# Deliberately .PHONY rather than a file rule on the library path: the
# go-cabi target builds the SAME path with default features (no uniffi), so
# a file rule lets make skip the rebuild and uniffi-bindgen then fails with
# "No UniFFI metadata found". cargo's own incremental build makes the
# unconditional invocation cheap.
uniffi-lib:
	cargo build --release --features uniffi

bindings-kotlin: uniffi-lib
	@mkdir -p $(KOTLIN_DIR)
	cargo run --release --features uniffi --bin uniffi-bindgen -- generate \
		--library $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language kotlin --out-dir $(KOTLIN_DIR)
	@echo "Kotlin bindings generated in $(KOTLIN_DIR)"

bindings-swift: uniffi-lib
	@mkdir -p $(SWIFT_DIR)
	cargo run --release --features uniffi --bin uniffi-bindgen -- generate \
		--library $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language swift --out-dir $(SWIFT_DIR)
	@echo "Swift bindings generated in $(SWIFT_DIR)"

check-bindings: bindings-kotlin bindings-swift
	@git diff --exit-code -- $(BINDINGS_DIR) \
		|| (echo "ERROR: generated bindings are stale; commit the regenerated files" && exit 1)

# ── Go C-ABI ────────────────────────────────────────────────────────
#
# Built with the crate's DEFAULT features: go_ffi.rs is always compiled in
# (no #[cfg] on that module, unlike ffi_api.rs), and omitting uniffi keeps
# this artifact free of scaffolding cgo callers have no use for. Both the
# shared and the static library are staged; vc links the .a for a
# fully static musl build.

go-cabi: $(GO_CABI_DIR)/$(LIB_NAME).$(HOST_LIB_EXT) $(GO_CABI_DIR)/$(LIB_NAME).a $(GO_CABI_DIR)/zk_cred_bbs_go.h
	@echo "Go C-ABI library + header staged in $(GO_CABI_DIR)"

# Same hazard in reverse: force the default-feature build rather than
# reusing whatever the uniffi target last left at target/release.
$(GO_CABI_DIR)/$(LIB_NAME).$(HOST_LIB_EXT): $(GO_CABI_DIR)/zk_cred_bbs_go.h FORCE
	cargo build --release
	@mkdir -p $(GO_CABI_DIR)
	cp $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT) $(GO_CABI_DIR)/

$(GO_CABI_DIR)/$(LIB_NAME).a: $(GO_CABI_DIR)/zk_cred_bbs_go.h FORCE
	cargo build --release
	@mkdir -p $(GO_CABI_DIR)
	cp $(BUILD_DIR)/release/$(LIB_NAME).a $(GO_CABI_DIR)/

$(GO_CABI_DIR)/zk_cred_bbs_go.h: include/zk_cred_bbs_go.h
	@mkdir -p $(GO_CABI_DIR)
	cp include/zk_cred_bbs_go.h $(GO_CABI_DIR)/

go-smoketest: go-cabi
	cd go-cabi-smoketest && \
		CGO_CFLAGS="-I$(CURDIR)/$(GO_CABI_DIR)" \
		CGO_LDFLAGS="-L$(CURDIR)/$(GO_CABI_DIR) -lzk_cred_bbs" \
		LD_LIBRARY_PATH="$(CURDIR)/$(GO_CABI_DIR)" \
		GOWORK=off \
		go test -v ./...

# A hand-written header is only as good as the check that it still matches.
# The Rust side asserts every constant at compile time; this re-derives them
# from the header and compares.
check-go-header:
	python3 tools/check_go_header.py

# ── Browser / npm ───────────────────────────────────────────────────

wasm:
	@command -v wasm-pack >/dev/null 2>&1 || \
		(echo "ERROR: wasm-pack not found — cargo install wasm-pack" && exit 1)
	RUSTFLAGS='$(WASM_RUSTFLAGS)' wasm-pack build --release --target web \
		--out-dir $(WASM_DIR) -- --features wasm
	@echo "wasm package built in $(WASM_DIR)"

FORCE:

clean:
	cargo clean
	rm -rf $(BINDINGS_DIR) $(WASM_DIR)
