# NONOS microkernel build.
#
# Public targets: `nonos-mk-*`. `make` with no args prints the help
# table; no target builds silently. The old monolithic recipes (USB,
# ISO, VirtualBox, ci-release, web-iso, release) sit untouched in
# `docs/legacy/Makefile.monolithic`. `nonos-mk-release` is a stub that
# exits non-zero until the microkernel release pipeline ships.
#
# Cheat sheet:
#   make nonos-mk              microkernel-capsules runtime baseline
#   make nonos-mk-run          QEMU + OVMF
#   make nonos-mk-boot-ramfs   ramfs capsule round trip
#   make nonos-mk-boot-keyring keyring capsule round trip
#   make nonos-mk-verify       static gates + capsules build + symbol scan
#   make nonos-mk-test         verify + both boot harnesses
#
# A few old names (`kernel-capsules`, `kernel-with-keyring`, `boot-test`,
# etc.) forward to `nonos-mk-*` for transitional compatibility. See the
# bottom of the file.

.PHONY: help

# Public nonos-mk-* targets
.PHONY: nonos-mk
.PHONY: nonos-mk-check nonos-mk-core nonos-mk-capsules
.PHONY: nonos-mk-ramfs-test nonos-mk-keyring-test nonos-mk-entropy-test nonos-mk-crypto-hash-test nonos-mk-vfs-test
.PHONY: nonos-mk-libc nonos-mk-proof-io nonos-mk-ramfs nonos-mk-keyring nonos-mk-entropy nonos-mk-crypto nonos-mk-vfs
.PHONY: nonos-mk-userland-clean
.PHONY: nonos-mk-bootloader nonos-mk-sign nonos-mk-attest nonos-mk-esp
.PHONY: nonos-mk-run nonos-mk-run-serial nonos-mk-debug
.PHONY: nonos-mk-boot-ramfs nonos-mk-boot-keyring nonos-mk-boot-entropy nonos-mk-boot-crypto-hash nonos-mk-boot-vfs
.PHONY: nonos-mk-static nonos-mk-scan
.PHONY: nonos-mk-verify nonos-mk-verify-fast
.PHONY: nonos-mk-test nonos-mk-host-test
.PHONY: nonos-mk-release
.PHONY: nonos-mk-clean nonos-mk-clean-all nonos-mk-distclean
.PHONY: nonos-mk-fmt
.PHONY: nonos-mk-toolchain nonos-mk-check-deps
.PHONY: nonos-mk-ensure-signing-key nonos-mk-ensure-zk-keys nonos-mk-zk-tools

# Compatibility aliases (transitional, do not remove until callers move)
.PHONY: kernel-capsules kernel-keyring-smoketest kernel-ramfs-smoketest
.PHONY: kernel-with-keyring kernel-microkernel-keyring-smoketest
.PHONY: boot-test ramfs-boot-test
.PHONY: check-static clean-kernel-only microkernel-symbol-scan

# Default target: print help, never build silently.

.DEFAULT_GOAL := help

# Configuration

BOOTLOADER_DIR := nonos-bootloader
TARGET_DIR     := target
ESP_DIR        := $(TARGET_DIR)/esp
KEYS_DIR       := $(BOOTLOADER_DIR)/keys

export SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date +%s)
export CARGO_INCREMENTAL := 0

export PATH := $(HOME)/.cargo/bin:$(PATH)
TOOLCHAIN := nightly-2026-01-16
CARGO     := $(HOME)/.cargo/bin/cargo
RUSTUP    := $(HOME)/.cargo/bin/rustup

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    ifeq ($(UNAME_M),arm64)
        HOST_TARGET := aarch64-apple-darwin
    else
        HOST_TARGET := x86_64-apple-darwin
    endif
    SDK_PATH   := /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
    SDK_EXISTS := $(shell test -d $(SDK_PATH) && echo yes)
    ifeq ($(SDK_EXISTS),yes)
        SDK_FLAGS := SDKROOT=$(SDK_PATH) \
                     AR=/Library/Developer/CommandLineTools/usr/bin/ar \
                     CC=/Library/Developer/CommandLineTools/usr/bin/clang \
                     PATH="/Library/Developer/CommandLineTools/usr/bin:$$PATH"
    else
        SDK_FLAGS :=
    endif
    SHA256 := shasum -a 256
else ifeq ($(UNAME_S),Linux)
    HOST_TARGET := x86_64-unknown-linux-gnu
    SDK_FLAGS   :=
    SHA256      := sha256sum
else
    $(error Unsupported host platform: $(UNAME_S))
endif

# Signing key. Auto-generated on first use.
SIGNING_KEY ?= $(KEYS_DIR)/signing_key_v1.bin

# ZK ceremony paths.
ZK_CIRCUIT_DIR   := $(BOOTLOADER_DIR)/tools/nonos-attestation-circuit
ZK_KEYS_DIR      := $(ZK_CIRCUIT_DIR)/generated_keys
ZK_PROVING_KEY   := $(ZK_KEYS_DIR)/attestation_proving_key.bin
ZK_VERIFYING_KEY := $(ZK_KEYS_DIR)/attestation_verifying_key.bin
ZK_KEY_SEED      := nonos-production-attestation-v1-2026
ZK_TOOL          := $(ZK_CIRCUIT_DIR)/target/$(HOST_TARGET)/release/generate-keys
EMBED_TOOL       := $(BOOTLOADER_DIR)/tools/embed-zk-proof/target/$(HOST_TARGET)/release/embed-zk-proof

# QEMU + OVMF discovery.
QEMU := qemu-system-x86_64
ifeq ($(UNAME_S),Darwin)
    OVMF ?= $(shell \
        if [ -f firmware/OVMF.fd ]; then echo firmware/OVMF.fd; \
        elif [ -f /opt/homebrew/share/qemu/edk2-x86_64-code.fd ]; then echo /opt/homebrew/share/qemu/edk2-x86_64-code.fd; \
        elif [ -f /usr/local/share/qemu/edk2-x86_64-code.fd ]; then echo /usr/local/share/qemu/edk2-x86_64-code.fd; \
        fi)
    OVMF_VARS ?= $(shell \
        if [ -f firmware/OVMF_VARS.fd ]; then echo firmware/OVMF_VARS.fd; \
        elif [ -f /opt/homebrew/share/qemu/edk2-i386-vars.fd ]; then echo /opt/homebrew/share/qemu/edk2-i386-vars.fd; \
        elif [ -f /usr/local/share/qemu/edk2-i386-vars.fd ]; then echo /usr/local/share/qemu/edk2-i386-vars.fd; \
        fi)
else
    # Walk the candidate list shipped by the major Linux distros.
    OVMF ?= $(shell \
        for f in \
            /usr/share/OVMF/OVMF_CODE_4M.fd \
            /usr/share/OVMF/OVMF_CODE.fd \
            /usr/share/qemu/OVMF.fd \
            /usr/share/ovmf/OVMF.fd \
            /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
            /usr/share/edk2/ovmf/OVMF_CODE.fd ; do \
            if [ -r $$f ]; then echo $$f; exit 0; fi; \
        done)
    OVMF_VARS ?= $(shell \
        for f in \
            /usr/share/OVMF/OVMF_VARS_4M.fd \
            /usr/share/OVMF/OVMF_VARS.fd \
            /usr/share/qemu/OVMF_VARS.fd \
            /usr/share/ovmf/OVMF_VARS.fd \
            /usr/share/edk2-ovmf/x64/OVMF_VARS.fd \
            /usr/share/edk2/ovmf/OVMF_VARS.fd ; do \
            if [ -r $$f ]; then echo $$f; exit 0; fi; \
        done)
endif

QEMU_MEM := 2G
QEMU_CPU := max
QEMU_SMP := 2
QEMU_NET := -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:80
QEMU_USB := -device qemu-xhci,id=xhci -device usb-tablet,bus=xhci.0
QEMU_RNG := -device virtio-rng-pci

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Top-level: nonos-mk = build the microkernel-capsules runtime baseline.

nonos-mk: nonos-mk-capsules
	@echo
	@echo "Built microkernel-capsules ($(VERSION))."
	@echo "  make nonos-mk-esp           package the ESP for QEMU"
	@echo "  make nonos-mk-run           boot under QEMU + OVMF"
	@echo "  make nonos-mk-verify        static gates + symbol scan"
	@echo "  make nonos-mk-test          verify + both boot harnesses"

# Toolchain + key bootstrap

nonos-mk-toolchain:
	@test -f $(RUSTUP) || { echo "rustup not found. Install from https://rustup.rs"; exit 1; }
	@$(RUSTUP) toolchain install $(TOOLCHAIN) 2>/dev/null || true
	@$(RUSTUP) target add x86_64-unknown-uefi --toolchain $(TOOLCHAIN) 2>/dev/null || true
	@$(RUSTUP) component add rust-src clippy rustfmt --toolchain $(TOOLCHAIN) 2>/dev/null || true

nonos-mk-check-deps: nonos-mk-toolchain

$(SIGNING_KEY):
	@echo "Generating signing key (Ed25519 seed)..."
	@mkdir -p $(KEYS_DIR)
	@head -c 32 /dev/urandom > $@
	@echo "Wrote $@"

nonos-mk-ensure-signing-key: $(SIGNING_KEY)

# ZK attestation: ceremony tools + ceremony keys + embed tool

$(ZK_TOOL): nonos-mk-check-deps
	@echo "Building ZK attestation tools..."
	@cd $(ZK_CIRCUIT_DIR) && RUSTFLAGS="" RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --bin generate-keys --bin generate-proof --target $(HOST_TARGET)

$(ZK_PROVING_KEY): $(ZK_TOOL)
	@echo "Running trusted setup for ZK circuit..."
	@mkdir -p $(ZK_KEYS_DIR)
	@$(ZK_TOOL) generate --output $(ZK_KEYS_DIR) --seed "$(ZK_KEY_SEED)" --allow-unsigned --print-program-hash
	@cp $(ZK_VERIFYING_KEY) $(ZK_KEYS_DIR)/vk_attestation_program.bin
	@cp $(ZK_VERIFYING_KEY) $(ZK_KEYS_DIR)/vk_boot_authority.bin
	@cp $(ZK_VERIFYING_KEY) $(ZK_KEYS_DIR)/vk_update_authority.bin
	@cp $(ZK_VERIFYING_KEY) $(ZK_KEYS_DIR)/vk_recovery_key.bin

$(ZK_VERIFYING_KEY): $(ZK_PROVING_KEY)

nonos-mk-ensure-zk-keys: $(ZK_PROVING_KEY) $(ZK_VERIFYING_KEY)
nonos-mk-zk-tools: $(ZK_TOOL)

$(EMBED_TOOL): nonos-mk-check-deps
	@echo "Building ZK embed tool..."
	@cd $(BOOTLOADER_DIR)/tools/embed-zk-proof && RUSTFLAGS="" RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --target $(HOST_TARGET)

# Bootloader

$(BOOTLOADER_DIR)/target/x86_64-unknown-uefi/release/nonos_boot.efi: \
		nonos-mk-check-deps nonos-mk-ensure-signing-key nonos-mk-ensure-zk-keys
	@echo "Building UEFI bootloader..."
	$(eval SIGNING_KEY_ABS := $(if $(filter /%,$(SIGNING_KEY)),$(SIGNING_KEY),$(shell pwd)/$(SIGNING_KEY)))
	@cd $(BOOTLOADER_DIR) && \
		NONOS_SIGNING_KEY=$(SIGNING_KEY_ABS) \
		NONOS_ZK_CEREMONY_DIR=$(shell pwd)/$(ZK_KEYS_DIR) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --target x86_64-unknown-uefi --release --features zk-groth16

nonos-mk-bootloader: $(BOOTLOADER_DIR)/target/x86_64-unknown-uefi/release/nonos_boot.efi

# Userland capsules

USERLAND_DIR  := userland
USERLAND_LIBC := $(USERLAND_DIR)/libc/target/x86_64-nonos-user/release/libnonos_libc.a
PROOF_IO_BIN  := $(USERLAND_DIR)/capsule_proof_io/target/x86_64-nonos-user/release/proof_io
RAMFS_BIN     := $(USERLAND_DIR)/capsule_ramfs/target/x86_64-nonos-user/release/ramfs
KEYRING_BIN   := $(USERLAND_DIR)/capsule_keyring/target/x86_64-nonos-user/release/keyring
ENTROPY_BIN   := $(USERLAND_DIR)/capsule_entropy/target/x86_64-nonos-user/release/entropy

$(USERLAND_LIBC):
	@echo "Building userland libc..."
	@cd $(USERLAND_DIR)/libc && \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --target ../x86_64-nonos-user.json \
		-Zbuild-std=core

nonos-mk-libc: $(USERLAND_LIBC)

$(PROOF_IO_BIN): $(USERLAND_LIBC)
	@echo "Building proof_io capsule..."
	@cd $(USERLAND_DIR)/capsule_proof_io && \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --target ../x86_64-nonos-user.json \
		-Zbuild-std=core

nonos-mk-proof-io: $(PROOF_IO_BIN)

$(RAMFS_BIN): $(USERLAND_LIBC)
	@echo "Building ramfs capsule..."
	@cd $(USERLAND_DIR)/capsule_ramfs && \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --target ../x86_64-nonos-user.json \
		-Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

nonos-mk-ramfs: $(RAMFS_BIN)

$(KEYRING_BIN): $(USERLAND_LIBC)
	@echo "Building keyring capsule..."
	@cd $(USERLAND_DIR)/capsule_keyring && \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --target ../x86_64-nonos-user.json \
		-Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

nonos-mk-keyring: $(KEYRING_BIN)

$(ENTROPY_BIN): $(USERLAND_LIBC)
	@echo "Building entropy capsule..."
	@cd $(USERLAND_DIR)/capsule_entropy && \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --target ../x86_64-nonos-user.json \
		-Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

nonos-mk-entropy: $(ENTROPY_BIN)

CRYPTO_BIN := $(USERLAND_DIR)/capsule_crypto/target/x86_64-nonos-user/release/crypto

$(CRYPTO_BIN): $(USERLAND_LIBC)
	@echo "Building crypto capsule..."
	@cd $(USERLAND_DIR)/capsule_crypto && \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --target ../x86_64-nonos-user.json \
		-Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

nonos-mk-crypto: $(CRYPTO_BIN)

VFS_BIN := $(USERLAND_DIR)/capsule_vfs/target/x86_64-nonos-user/release/vfs

$(VFS_BIN): $(USERLAND_LIBC)
	@echo "Building vfs capsule..."
	@cd $(USERLAND_DIR)/capsule_vfs && \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --target ../x86_64-nonos-user.json \
		-Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

nonos-mk-vfs: $(VFS_BIN)

nonos-mk-userland-clean:
	@echo "Removing userland build state..."
	@rm -rf $(USERLAND_DIR)/libc/target \
		$(USERLAND_DIR)/capsule_proof_io/target \
		$(USERLAND_DIR)/capsule_ramfs/target \
		$(USERLAND_DIR)/capsule_keyring/target \
		$(USERLAND_DIR)/capsule_entropy/target \
		$(USERLAND_DIR)/capsule_crypto/target \
		$(USERLAND_DIR)/capsule_vfs/target

# Kernel — every target spells the profile out explicitly.

KERNEL_BUILD_FLAGS := --release --target x86_64-nonos.json \
		-Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

KERNEL_SIGNING_KEY = $(if $(filter /%,$(SIGNING_KEY)),$(SIGNING_KEY),$(shell pwd)/$(SIGNING_KEY))

# Kernel ELF artefact rule, no-features default (resolves to
# microkernel-core via Cargo.toml). Phony deps stay off this rule so a
# chain walk does not invalidate kernels built with a feature variant.
$(TARGET_DIR)/x86_64-nonos/release/nonos-kernel: $(SIGNING_KEY)
	@echo "Building kernel (default = microkernel-core)..."
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(KERNEL_SIGNING_KEY) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build $(KERNEL_BUILD_FLAGS)

nonos-mk-check: nonos-mk-check-deps nonos-mk-ensure-signing-key
	@echo "cargo check (microkernel-core)..."
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(KERNEL_SIGNING_KEY) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) check $(KERNEL_BUILD_FLAGS) \
		--no-default-features --features microkernel-core

nonos-mk-core: nonos-mk-check-deps nonos-mk-ensure-signing-key
	@echo "Building kernel (microkernel-core, no capsules)..."
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(KERNEL_SIGNING_KEY) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build $(KERNEL_BUILD_FLAGS) \
		--no-default-features --features microkernel-core

nonos-mk-capsules: $(PROOF_IO_BIN) $(RAMFS_BIN) $(KEYRING_BIN) \
		nonos-mk-check-deps nonos-mk-ensure-signing-key
	@echo "Building kernel (microkernel-capsules: proof_io + ramfs + keyring)..."
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(KERNEL_SIGNING_KEY) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build $(KERNEL_BUILD_FLAGS) \
		--no-default-features --features microkernel-capsules

nonos-mk-ramfs-test: $(PROOF_IO_BIN) $(RAMFS_BIN) \
		nonos-mk-check-deps nonos-mk-ensure-signing-key
	@echo "Building kernel (ramfs smoketest)..."
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(KERNEL_SIGNING_KEY) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build $(KERNEL_BUILD_FLAGS) \
		--features nonos-capsule-proof-io,nonos-capsule-ramfs,nonos-ramfs-smoketest

nonos-mk-keyring-test: $(PROOF_IO_BIN) $(RAMFS_BIN) $(KEYRING_BIN) \
		nonos-mk-check-deps nonos-mk-ensure-signing-key
	@echo "Building kernel (microkernel-keyring-smoketest)..."
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(KERNEL_SIGNING_KEY) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build $(KERNEL_BUILD_FLAGS) \
		--no-default-features --features microkernel-keyring-smoketest

nonos-mk-entropy-test: $(PROOF_IO_BIN) $(ENTROPY_BIN) \
		nonos-mk-check-deps nonos-mk-ensure-signing-key
	@echo "Building kernel (microkernel-entropy-smoketest)..."
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(KERNEL_SIGNING_KEY) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build $(KERNEL_BUILD_FLAGS) \
		--no-default-features --features microkernel-entropy-smoketest

nonos-mk-crypto-hash-test: $(PROOF_IO_BIN) $(CRYPTO_BIN) \
		nonos-mk-check-deps nonos-mk-ensure-signing-key
	@echo "Building kernel (microkernel-crypto-hash-smoketest)..."
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(KERNEL_SIGNING_KEY) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build $(KERNEL_BUILD_FLAGS) \
		--no-default-features --features microkernel-crypto-hash-smoketest

nonos-mk-vfs-test: $(PROOF_IO_BIN) $(VFS_BIN) \
		nonos-mk-check-deps nonos-mk-ensure-signing-key
	@echo "Building kernel (microkernel-vfs-smoketest)..."
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(KERNEL_SIGNING_KEY) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build $(KERNEL_BUILD_FLAGS) \
		--no-default-features --features microkernel-vfs-smoketest

# Sign + attest + ESP packaging

$(TARGET_DIR)/kernel_signed.bin: $(TARGET_DIR)/x86_64-nonos/release/nonos-kernel $(SIGNING_KEY)
	@echo "Signing kernel (Ed25519)..."
	@mkdir -p $(TARGET_DIR)
ifeq ($(UNAME_S),Darwin)
	@/usr/bin/python3 scripts/sign_kernel.py $< $(SIGNING_KEY) $@
else
	@python3 scripts/sign_kernel.py $< $(SIGNING_KEY) $@
endif

nonos-mk-sign: $(TARGET_DIR)/kernel_signed.bin

$(TARGET_DIR)/kernel_attested.bin: $(TARGET_DIR)/kernel_signed.bin $(EMBED_TOOL) $(ZK_PROVING_KEY)
	@echo "Embedding ZK attestation proof..."
	@$(EMBED_TOOL) --input $< --output $@ --proving-key $(ZK_PROVING_KEY) --seed "$(ZK_KEY_SEED)" --verbose

nonos-mk-attest: $(TARGET_DIR)/kernel_attested.bin

nonos-mk-esp: \
		$(BOOTLOADER_DIR)/target/x86_64-unknown-uefi/release/nonos_boot.efi \
		$(TARGET_DIR)/kernel_attested.bin
	@echo "Packaging EFI System Partition..."
	@mkdir -p $(ESP_DIR)/EFI/Boot $(ESP_DIR)/EFI/nonos
	@cp $(BOOTLOADER_DIR)/target/x86_64-unknown-uefi/release/nonos_boot.efi $(ESP_DIR)/EFI/Boot/BOOTX64.EFI
	@cp $(TARGET_DIR)/kernel_attested.bin $(ESP_DIR)/EFI/nonos/kernel.bin
	@printf "timeout=0\ndefault=nonos\n" > $(ESP_DIR)/EFI/nonos/boot.cfg
	@echo 'fs0:\EFI\Boot\BOOTX64.EFI' > $(ESP_DIR)/startup.nsh
	@echo "ESP ready at $(ESP_DIR)"

# QEMU

nonos-mk-run: nonos-mk-esp
	@echo "Booting NONOS in QEMU..."
	@echo "  SSH:  ssh -p 2222 localhost"
	@echo "  HTTP: http://localhost:8080"
	@echo "  Quit: Ctrl+A then X"
	@$(QEMU) -m $(QEMU_MEM) -cpu $(QEMU_CPU) -smp $(QEMU_SMP) -machine q35 \
		-drive "format=raw,file=fat:rw:$(ESP_DIR)" \
		-drive if=pflash,format=raw,unit=0,readonly=on,file="$(OVMF)" \
		-drive if=pflash,format=raw,unit=1,readonly=on,file="$(OVMF_VARS)" \
		$(QEMU_NET) $(QEMU_USB) $(QEMU_RNG) \
		-serial mon:stdio -vga std -no-reboot

nonos-mk-run-serial: nonos-mk-esp
	@$(QEMU) -m $(QEMU_MEM) -cpu $(QEMU_CPU) -smp $(QEMU_SMP) -machine q35 \
		-drive "format=raw,file=fat:rw:$(ESP_DIR)" \
		-drive if=pflash,format=raw,readonly=on,file="$(OVMF)" \
		$(QEMU_NET) $(QEMU_RNG) \
		-serial mon:stdio -display none -no-reboot

nonos-mk-debug: nonos-mk-esp
	@echo "QEMU listening for GDB on :1234   (gdb -ex 'target remote :1234')"
	@$(QEMU) -m $(QEMU_MEM) -cpu $(QEMU_CPU) -smp $(QEMU_SMP) -machine q35 \
		-drive "format=raw,file=fat:rw:$(ESP_DIR)" \
		-drive if=pflash,format=raw,readonly=on,file="$(OVMF)" \
		$(QEMU_NET) $(QEMU_RNG) \
		-serial mon:stdio -vga std -s -S -no-reboot

# Boot-test harnesses

nonos-mk-boot-ramfs:
	@./tests/boot/ramfs_round_trip.sh

nonos-mk-boot-keyring:
	@./tests/boot/keyring_round_trip.sh

nonos-mk-boot-entropy:
	@./tests/boot/entropy_round_trip.sh

nonos-mk-boot-crypto-hash:
	@./tests/boot/crypto_hash_round_trip.sh

nonos-mk-boot-vfs:
	@./tests/boot/vfs_round_trip.sh

# Verify

nonos-mk-static:
	@./tools/ci/run-static-checks.sh

MICROKERNEL_BIN := $(TARGET_DIR)/x86_64-nonos/release/nonos-kernel

# Patterns are matched against demangled `nm` output, so each entry is
# a qualified module-path fragment, not a raw substring. Raw substrings
# false-match the v0 mangling: `ext4` would hit `process::context::full`
# because the mangled name contains `7context4full`. The leading and
# trailing `::` anchors match the path separator emitted by --demangle.
MICROKERNEL_FORBIDDEN_SYMBOLS := \
  ::ext4:: ::fat32:: ::btrfs:: ::xfs:: ::f2fs:: ::squashfs:: ::overlayfs:: ::nfs:: \
  ::ahci:: ::nvme:: ::virtio_blk:: ::dm_crypt:: ::md_raid:: ::zswap:: ::hibernate:: \
  ::desktop:: ::graphics:: ::shell:: ::apps_service:: ::agents_service:: ::network_service::

nonos-mk-scan:
	@echo "Scanning microkernel image for legacy symbols..."
	@if [ ! -f "$(MICROKERNEL_BIN)" ]; then \
		echo "FAIL: microkernel binary not found at $(MICROKERNEL_BIN)"; \
		echo "      build first via 'make nonos-mk-capsules'"; \
		exit 1; \
	fi
	@dump=$$(mktemp); \
	if nm --demangle "$(MICROKERNEL_BIN)" >$$dump 2>/dev/null; then :; \
	else nm "$(MICROKERNEL_BIN)" 2>/dev/null >$$dump; fi; \
	fail=0; \
	for sym in $(MICROKERNEL_FORBIDDEN_SYMBOLS); do \
		hits=$$(grep -F "$$sym" $$dump | head -3); \
		if [ -n "$$hits" ]; then \
			echo "FAIL: image contains symbol matching '$$sym':"; \
			echo "$$hits"; \
			fail=1; \
		fi; \
	done; \
	rm -f $$dump; \
	if [ $$fail -ne 0 ]; then exit 1; fi
	@bash tools/ci/scan-microkernel-symbols.sh "$(MICROKERNEL_BIN)"
	@echo "PASS: no legacy-tree symbols"

# Fast lane: static gates only, no kernel build.
nonos-mk-verify-fast: nonos-mk-static

# Full lane: static gates, then build the runtime baseline, then scan.
nonos-mk-verify: nonos-mk-static nonos-mk-capsules nonos-mk-scan

# Full test: verify + both QEMU boot harnesses.
nonos-mk-test: nonos-mk-verify nonos-mk-boot-ramfs nonos-mk-boot-keyring

# Host-mode crate tests (currently flaky on TSC; tracked in
# docs/production-roadmap/master-execution-checklist.md F1).
nonos-mk-host-test:
	@RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) test --lib --features std --target $(HOST_TARGET)
	@cd $(BOOTLOADER_DIR) && RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) test

# Release pipeline (paused)

nonos-mk-release:
	@echo
	@echo "release pipeline paused"
	@echo
	@echo "  The legacy 'release' / 'ci-release' / 'iso' / 'usb' / 'web-iso'"
	@echo "  targets produced the old monolithic-kernel artefacts and have"
	@echo "  been withdrawn from the active Makefile. A microkernel-shaped"
	@echo "  replacement is staged for a later CI step."
	@echo
	@echo "  Legacy recipes:  docs/legacy/Makefile.monolithic"
	@echo "  Status note:     docs/production-roadmap/master-execution-checklist.md"
	@echo
	@exit 1

# Clean

# Default `nonos-mk-clean` is kernel-only — userland artefacts survive
# so the next kernel build re-uses the existing capsule binaries.
nonos-mk-clean:
	@echo "Removing kernel build target (userland targets preserved)..."
	@rm -rf $(TARGET_DIR)/x86_64-nonos
	@rm -f $(TARGET_DIR)/kernel_signed.bin $(TARGET_DIR)/kernel_attested.bin

nonos-mk-clean-all:
	@echo "Cleaning kernel + bootloader + ESP..."
	@cd $(BOOTLOADER_DIR) && $(CARGO) clean 2>/dev/null || true
	@$(CARGO) clean 2>/dev/null || true
	@rm -rf $(TARGET_DIR)

nonos-mk-distclean: nonos-mk-clean-all
	@echo "Removing signing + ZK keys..."
	@rm -rf $(BOOTLOADER_DIR)/target target
	@rm -f $(SIGNING_KEY)
	@rm -rf $(ZK_KEYS_DIR)

nonos-mk-fmt:
	@RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) fmt
	@cd $(BOOTLOADER_DIR) && RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) fmt

# Help (default target)

help:
	@echo "NONOS microkernel build"
	@echo
	@echo "Build:"
	@echo "  make nonos-mk                 microkernel-capsules runtime baseline"
	@echo "  make nonos-mk-core            kernel only (microkernel-core, no capsules)"
	@echo "  make nonos-mk-check           cargo check (microkernel-core)"
	@echo "  make nonos-mk-capsules        microkernel-capsules build"
	@echo "  make nonos-mk-ramfs-test      ramfs smoketest profile"
	@echo "  make nonos-mk-keyring-test    keyring smoketest profile"
	@echo "  make nonos-mk-entropy-test    entropy smoketest profile"
	@echo "  make nonos-mk-crypto-hash-test crypto hash smoketest profile"
	@echo "  make nonos-mk-vfs-test        vfs smoketest profile"
	@echo
	@echo "Userland capsules:"
	@echo "  make nonos-mk-libc nonos-mk-proof-io nonos-mk-ramfs nonos-mk-keyring"
	@echo "  make nonos-mk-userland-clean"
	@echo
	@echo "Sign / attest / package:"
	@echo "  make nonos-mk-sign            Ed25519 manifest signature"
	@echo "  make nonos-mk-attest          Groth16 attestation proof"
	@echo "  make nonos-mk-bootloader      UEFI bootloader"
	@echo "  make nonos-mk-esp             EFI System Partition for QEMU"
	@echo
	@echo "Run:"
	@echo "  make nonos-mk-run             QEMU + OVMF (SSH:2222, HTTP:8080)"
	@echo "  make nonos-mk-run-serial      headless serial-only"
	@echo "  make nonos-mk-debug           QEMU + GDB on :1234"
	@echo
	@echo "Verify:"
	@echo "  make nonos-mk-static          CI static gates"
	@echo "  make nonos-mk-scan            symbol scan over kernel image"
	@echo "  make nonos-mk-verify-fast     static gates only (no kernel build)"
	@echo "  make nonos-mk-verify          static gates + capsules build + scan"
	@echo "  make nonos-mk-boot-ramfs      ramfs capsule round trip under QEMU"
	@echo "  make nonos-mk-boot-keyring    keyring capsule round trip under QEMU"
	@echo "  make nonos-mk-boot-entropy    entropy capsule round trip under QEMU"
	@echo "  make nonos-mk-boot-crypto-hash crypto hash round trip under QEMU"
	@echo "  make nonos-mk-boot-vfs        vfs capsule round trip under QEMU"
	@echo "  make nonos-mk-test            verify + both boot harnesses"
	@echo "  make nonos-mk-host-test       host-mode cargo tests (flaky; see roadmap)"
	@echo
	@echo "Release:"
	@echo "  make nonos-mk-release         (paused; see message)"
	@echo
	@echo "Clean:"
	@echo "  make nonos-mk-clean           kernel artefacts only (preserve userland)"
	@echo "  make nonos-mk-clean-all       kernel + bootloader + ESP"
	@echo "  make nonos-mk-distclean       above + signing + ZK keys"
	@echo
	@echo "Aux:"
	@echo "  make nonos-mk-toolchain       install nightly + components"
	@echo "  make nonos-mk-fmt             cargo fmt across kernel + bootloader"
	@echo
	@echo "Environment:"
	@echo "  SIGNING_KEY=<path>            override signing key (default auto-gen)"
	@echo "  OVMF=<path>                   override OVMF firmware discovery"

# Compatibility aliases (transitional; remove once callers migrate)

kernel-capsules:                       nonos-mk-capsules
kernel-with-keyring:                   nonos-mk-capsules
kernel-keyring-smoketest:              nonos-mk-keyring-test
kernel-microkernel-keyring-smoketest:  nonos-mk-keyring-test
kernel-ramfs-smoketest:                nonos-mk-ramfs-test
ramfs-boot-test:                       nonos-mk-boot-ramfs
boot-test:                             nonos-mk-boot-ramfs
check-static:                          nonos-mk-static
clean-kernel-only:                     nonos-mk-clean
microkernel-symbol-scan:               nonos-mk-scan
