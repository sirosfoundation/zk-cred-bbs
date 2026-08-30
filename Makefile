# zk-cred-bbs Makefile — binding generation for the four consumers.
#
# Mirrors zk-cred-vega's and zk-cred-longfellow's Makefiles (same org, same
# UniFFI/cross-compile shape). This crate has one more target than they do:
# a browser build, because wallet-frontend is meant to run this
# implementation rather than a parallel TypeScript one.
#
# Targets:
#   make ios               — cross-compile for iOS (device + simulator)
#   make xcframework       — package the iOS XCFramework for siros-sdk-swift
#   make android           — cross-compile for Android (arm64, armv7, x86_64)
#   make aar               — package the Android AAR
#   make publish-local     — install AAR + POM into ~/.m2 for local SDK builds
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

VERSION      := $(shell cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['version'])")

BUILD_DIR    := target
BINDINGS_DIR := bindings
KOTLIN_DIR   := $(BINDINGS_DIR)/kotlin
SWIFT_DIR    := $(BINDINGS_DIR)/swift
GO_CABI_DIR  := $(BUILD_DIR)/go-cabi
WASM_DIR     := pkg

# getrandom 0.4 needs an explicit backend on wasm32-unknown-unknown; without
# this the build fails at link time with a missing __getrandom symbol.
WASM_RUSTFLAGS := --cfg getrandom_backend="wasm_js"

# iOS cross-compilation. Requires macOS with Xcode toolchains - nothing
# below this line builds on Linux.
IOS_TARGETS     := aarch64-apple-ios
IOS_SIM_TARGETS := aarch64-apple-ios-sim x86_64-apple-ios
XCFRAMEWORK     := $(BUILD_DIR)/$(CRATE_NAME).xcframework

# Matches siros-wscd-manager's and zk-cred-longfellow's pin. An app links
# all three at once, and a lower target here would drag the whole product
# down to it.
export IPHONEOS_DEPLOYMENT_TARGET ?= 16.0

# Android cross-compilation (via cargo-ndk)
ANDROID_TARGETS := aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
AAR_DIR         := $(BUILD_DIR)/aar
MAVEN_GROUP     := org.siros
MAVEN_ARTIFACT  := zk-cred-bbs
MAVEN_LOCAL_DIR := $(HOME)/.m2/repository/$(subst .,/,$(MAVEN_GROUP))/$(MAVEN_ARTIFACT)/$(VERSION)

.PHONY: all bindings-kotlin bindings-swift uniffi-lib go-cabi go-smoketest keygen wasm \
        ios xcframework android aar pom publish-local check-go-header check-bindings \
        sdk-fixture clean FORCE

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

# The operator-facing binary. Behind the `cli` feature so the cross builds
# do not compile a host-only CLI for a phone.
keygen:
	cargo build --release --features cli --bin bbs-keygen
	@echo "built: $(BUILD_DIR)/release/bbs-keygen"

go-smoketest: go-cabi
	cd go-cabi-smoketest && \
		CGO_CFLAGS="-I$(CURDIR)/$(GO_CABI_DIR)" \
		CGO_LDFLAGS="-L$(CURDIR)/$(GO_CABI_DIR) -lzk_cred_bbs" \
		LD_LIBRARY_PATH="$(CURDIR)/$(GO_CABI_DIR)" \
		GOWORK=off \
		go test -v ./...

# The fixture the native SDKs test against. Regenerate after any change to
# the container or the claim mapping; the SDKs vendor a copy.
sdk-fixture:
	JWP_FIXTURE_OUT=test-vectors/sdk_jwp_fixture.json \
		cargo test --features uniffi --test ffi_jwp dump_sdk_fixture

# A hand-written header is only as good as the check that it still matches.
# The Rust side asserts every constant at compile time; this re-derives them
# from the header and compares.
check-go-header:
	python3 tools/check_go_header.py

# ── iOS cross-compilation (macOS + Xcode only) ──────────────────────

ios: $(foreach t,$(IOS_TARGETS) $(IOS_SIM_TARGETS),ios-$(t))

ios-%:
	cargo build --release --target $* --features uniffi

# ── XCFramework ─────────────────────────────────────────────────────

xcframework: ios bindings-swift
	@rm -rf $(XCFRAMEWORK)
	# One fat binary for the simulator: an XCFramework slice may carry
	# several architectures but only one platform.
	@mkdir -p $(BUILD_DIR)/ios-sim-universal
	lipo -create \
		$(foreach t,$(IOS_SIM_TARGETS),$(BUILD_DIR)/$(t)/release/$(LIB_NAME).a) \
		-output $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a
	# Plain "module", not "framework module": this is built from static
	# libraries (-library/-headers), not real .framework bundles, and
	# "framework module" fails to resolve at import time.
	#
	# Headers go under $(CRATE_NAME)FFI/ rather than at Headers/ root, and
	# that nesting is load-bearing. When an app links two or more
	# static-archive XCFrameworks together - and any app using this one
	# also links siros-wscd-manager's, and probably zk-cred-longfellow's -
	# Xcode's ProcessXCFramework step copies each one's Headers/ contents
	# into the SAME per-product include/ directory. A flat
	# Headers/module.modulemap from each collides there ("Multiple commands
	# produce .../include/module.modulemap") no matter what the module
	# inside is called. Nesting survives the copy, so each lands at
	# include/<crate>FFI/module.modulemap. Learned the hard way in
	# zk-cred-longfellow and siros-wscd-manager 0.7.3; do not flatten this.
	@rm -rf $(BUILD_DIR)/Headers
	@mkdir -p $(BUILD_DIR)/Headers/$(CRATE_NAME)FFI
	@cp $(SWIFT_DIR)/$(CRATE_NAME)FFI.h $(BUILD_DIR)/Headers/$(CRATE_NAME)FFI/
	@echo "module $(CRATE_NAME)FFI { header \"$(CRATE_NAME)FFI.h\" export * }" \
		> $(BUILD_DIR)/Headers/$(CRATE_NAME)FFI/module.modulemap
	xcodebuild -create-xcframework \
		-library $(BUILD_DIR)/aarch64-apple-ios/release/$(LIB_NAME).a \
		-headers $(BUILD_DIR)/Headers \
		-library $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a \
		-headers $(BUILD_DIR)/Headers \
		-output $(XCFRAMEWORK)
	@echo "XCFramework created at $(XCFRAMEWORK)"

# ── Android cross-compilation (requires cargo-ndk + the Android NDK) ──

android: $(foreach t,$(ANDROID_TARGETS),android-$(t))

android-%:
	cargo ndk --target $* --platform 28 -- build --release --features uniffi

# ── AAR packaging ────────────────────────────────────────────────────

aar: android
	@mkdir -p $(AAR_DIR)/jni/arm64-v8a $(AAR_DIR)/jni/armeabi-v7a $(AAR_DIR)/jni/x86_64
	cp $(BUILD_DIR)/aarch64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/arm64-v8a/
	cp $(BUILD_DIR)/armv7-linux-androideabi/release/$(LIB_NAME).so $(AAR_DIR)/jni/armeabi-v7a/
	cp $(BUILD_DIR)/x86_64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/x86_64/
	@echo '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.siros.zkcredbbs"/>' \
		> $(AAR_DIR)/AndroidManifest.xml
	@# The AAR ships only the native .so libraries; the UniFFI Kotlin
	@# bindings are consumed as vendored source by the SDK, so an empty
	@# classes.jar (required by the AAR layout) is enough. JNA comes in
	@# transitively via the POM.
	@mkdir -p $(BUILD_DIR)/aar-classes/META-INF
	@printf 'Manifest-Version: 1.0\n' > $(BUILD_DIR)/aar-classes/META-INF/MANIFEST.MF
	cd $(BUILD_DIR)/aar-classes && zip -qr ../aar/classes.jar .
	cd $(AAR_DIR) && zip -qr ../$(CRATE_NAME)-$(VERSION).aar .
	@echo "AAR created at $(BUILD_DIR)/$(CRATE_NAME)-$(VERSION).aar"

# ── Maven POM, so the AAR can be consumed by coordinates ─────────────

pom:
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<project xmlns="http://maven.apache.org/POM/4.0.0"' \
	  '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
	  '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
	  '  <modelVersion>4.0.0</modelVersion>' \
	  '  <groupId>$(MAVEN_GROUP)</groupId>' \
	  '  <artifactId>$(MAVEN_ARTIFACT)</artifactId>' \
	  '  <version>$(VERSION)</version>' \
	  '  <packaging>aar</packaging>' \
	  '  <dependencies>' \
	  '    <dependency>' \
	  '      <groupId>net.java.dev.jna</groupId>' \
	  '      <artifactId>jna</artifactId>' \
	  '      <version>5.14.0</version>' \
	  '      <type>aar</type>' \
	  '    </dependency>' \
	  '  </dependencies>' \
	  '</project>' \
	  > $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom
	@echo "POM written to $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom"

# ── Local Maven install, for building the SDK against an unreleased
#    crate: org.siros:zk-cred-bbs:$(VERSION) from mavenLocal ──────────

publish-local: aar pom
	@mkdir -p $(MAVEN_LOCAL_DIR)
	cp $(BUILD_DIR)/$(CRATE_NAME)-$(VERSION).aar \
	   $(MAVEN_LOCAL_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).aar
	cp $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom \
	   $(MAVEN_LOCAL_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom
	@echo "Installed to $(MAVEN_LOCAL_DIR)"

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
