# NONOS Build System
#
# Dev notes:
# - Pinned to nightly-2026-01-16 because newer nightlies have LLVM regressions
# - macOS needs explicit SDK paths or cross-compile fails silently
# - ZK keys live in nonos-bootloader/tools/nonos-attestation-circuit/generated_keys/
#
# CI usage:
#   SIGNING_KEY=/path/to/key make ci-release
#
# Local dev:
#   make            # build everything
#   make run        # boot in QEMU
#   make iso        # create nonos.iso

.PHONY: all bootloader kernel esp sign-kernel zk-tools generate-zk-keys generate-zk-proof
.PHONY: embed-zk-proof run run-serial debug iso usb clean distclean test fmt check help
.PHONY: check-deps show-vk ci-release checksums verify website-release

# Paths
KERNEL_DIR := .
BOOTLOADER_DIR := nonos-bootloader
TARGET_DIR := target
ESP_DIR := $(TARGET_DIR)/esp
RELEASE_DIR := $(TARGET_DIR)/release

# Signing key (32-byte Ed25519 seed)
SIGNING_KEY ?= $(shell pwd)/.keys/dev-signing.seed

# Host detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Rust toolchain
RUSTUP_HOME ?= $(HOME)/.rustup
CARGO_HOME ?= $(HOME)/.cargo
RUSTUP := $(CARGO_HOME)/bin/rustup
export RUSTUP_TOOLCHAIN := nightly-2026-01-16

ifeq ($(UNAME_S),Darwin)
    ifeq ($(UNAME_M),arm64)
        NIGHTLY_BIN := $(RUSTUP_HOME)/toolchains/nightly-2026-01-16-aarch64-apple-darwin/bin
    else
        NIGHTLY_BIN := $(RUSTUP_HOME)/toolchains/nightly-2026-01-16-x86_64-apple-darwin/bin
    endif
else
    NIGHTLY_BIN := $(RUSTUP_HOME)/toolchains/nightly-2026-01-16-x86_64-unknown-linux-gnu/bin
endif

# Use toolchain-specific cargo if available, otherwise rely on RUSTUP_TOOLCHAIN
ifneq ($(wildcard $(NIGHTLY_BIN)/cargo),)
    CARGO := $(NIGHTLY_BIN)/cargo
    export RUSTC := $(NIGHTLY_BIN)/rustc
    export RUSTDOC := $(NIGHTLY_BIN)/rustdoc
    export PATH := $(NIGHTLY_BIN):$(CARGO_HOME)/bin:$(PATH)
else
    CARGO := cargo
    export PATH := $(CARGO_HOME)/bin:$(PATH)
endif

# QEMU + OVMF
ifeq ($(UNAME_S),Darwin)
    QEMU := qemu-system-x86_64
    OVMF := $(shell pwd)/firmware/OVMF.fd
    OVMF_VARS := $(shell pwd)/firmware/OVMF_VARS.fd
    ifeq ($(wildcard $(OVMF)),)
        OVMF := $(shell \
            if [ -f /usr/local/share/qemu/edk2-x86_64-code.fd ]; then echo /usr/local/share/qemu/edk2-x86_64-code.fd; \
            elif [ -f /opt/homebrew/share/qemu/edk2-x86_64-code.fd ]; then echo /opt/homebrew/share/qemu/edk2-x86_64-code.fd; \
            fi)
        OVMF_VARS := $(shell \
            if [ -f /usr/local/share/qemu/edk2-i386-vars.fd ]; then echo /usr/local/share/qemu/edk2-i386-vars.fd; \
            elif [ -f /opt/homebrew/share/qemu/edk2-i386-vars.fd ]; then echo /opt/homebrew/share/qemu/edk2-i386-vars.fd; \
            fi)
    endif
else ifeq ($(UNAME_S),Linux)
    QEMU := qemu-system-x86_64
    OVMF := $(shell test -f /usr/share/OVMF/OVMF_CODE.fd && echo /usr/share/OVMF/OVMF_CODE.fd || echo /usr/share/edk2/ovmf/OVMF_CODE.fd)
    OVMF_VARS := $(shell test -f /usr/share/OVMF/OVMF_VARS.fd && echo /usr/share/OVMF/OVMF_VARS.fd || echo /usr/share/edk2/ovmf/OVMF_VARS.fd)
endif

# ZK attestation
ZK_CIRCUIT_DIR := $(BOOTLOADER_DIR)/tools/nonos-attestation-circuit
ZK_KEYS_DIR := $(ZK_CIRCUIT_DIR)/generated_keys
ZK_PROVING_KEY := $(ZK_KEYS_DIR)/attestation_proving_key.bin
ZK_VERIFYING_KEY := $(ZK_KEYS_DIR)/attestation_verifying_key.bin
ZK_PROOF_FILE := $(TARGET_DIR)/attestation_proof.bin
ZK_PUBLIC_INPUTS := $(TARGET_DIR)/public_inputs.bin
ZK_PROGRAM_HASH := fa02d10e8804169a47233e34a6ff3566248958adff55e1248d50304aff4ab230
ZK_KEY_SEED := nonos-production-attestation-v1-2026

# Build version
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
RELEASE_VERSION ?= 0.8.0-alpha

#
# Main targets
#

all: bootloader kernel esp
	@echo "Build complete: $(VERSION)"
	@echo "  make run   - boot in QEMU"
	@echo "  make iso   - create bootable ISO"

check-deps:
	@test -f $(CARGO) || { echo "Install rustup: https://rustup.rs"; exit 1; }
	@$(RUSTUP) show | grep -q nightly || $(RUSTUP) install nightly
	@$(RUSTUP) target list --installed | grep -q x86_64-unknown-uefi || $(RUSTUP) target add x86_64-unknown-uefi --toolchain nightly
	@$(RUSTUP) component add rust-src --toolchain nightly 2>/dev/null || true

bootloader: check-deps
	@echo "Building bootloader..."
	cd $(BOOTLOADER_DIR) && NONOS_SIGNING_KEY=$(SIGNING_KEY) $(CARGO) build --target x86_64-unknown-uefi --release --features zk-groth16

kernel: check-deps
	@echo "Building kernel..."
	@test -f $(SIGNING_KEY) || { echo "Signing key not found: $(SIGNING_KEY)"; exit 1; }
ifeq ($(UNAME_S),Darwin)
	SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
	AR=/Library/Developer/CommandLineTools/usr/bin/ar \
	CC=/Library/Developer/CommandLineTools/usr/bin/clang \
	NONOS_SIGNING_KEY=$(SIGNING_KEY) \
	PATH="/Library/Developer/CommandLineTools/usr/bin:$$PATH" \
	$(CARGO) build --release --target x86_64-nonos.json -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
else
	NONOS_SIGNING_KEY=$(SIGNING_KEY) $(CARGO) build --release --target x86_64-nonos.json -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
endif

sign-kernel: kernel
	@echo "Signing kernel..."
	@mkdir -p $(TARGET_DIR)
	@python3 scripts/sign_kernel.py \
		$(TARGET_DIR)/x86_64-nonos/release/nonos-kernel \
		$(SIGNING_KEY) \
		$(TARGET_DIR)/kernel_signed.bin

zk-tools:
	@echo "Building ZK tools..."
ifeq ($(UNAME_S),Darwin)
	cd $(ZK_CIRCUIT_DIR) && $(CARGO) build --release --bin generate-keys --bin generate-proof --target x86_64-apple-darwin
else
	cd $(ZK_CIRCUIT_DIR) && rm -rf target && RUSTFLAGS="" CARGO_UNSTABLE_BUILD_STD= $(CARGO) build --release --bin generate-keys --bin generate-proof --target x86_64-unknown-linux-gnu
endif

generate-zk-keys: zk-tools
	@echo "Generating ZK keys (trusted setup)..."
ifeq ($(UNAME_S),Darwin)
	$(ZK_CIRCUIT_DIR)/target/x86_64-apple-darwin/release/generate-keys generate \
		--output $(ZK_KEYS_DIR) --seed "$(ZK_KEY_SEED)" --allow-unsigned --print-program-hash
else
	$(ZK_CIRCUIT_DIR)/target/x86_64-unknown-linux-gnu/release/generate-keys generate \
		--output $(ZK_KEYS_DIR) --seed "$(ZK_KEY_SEED)" --allow-unsigned --print-program-hash
endif

generate-zk-proof: zk-tools
	@echo "Generating ZK proof..."
	@test -f $(ZK_PROVING_KEY) || { echo "No proving key. Run 'make generate-zk-keys' first."; exit 1; }
ifeq ($(UNAME_S),Darwin)
	$(ZK_CIRCUIT_DIR)/target/x86_64-apple-darwin/release/generate-proof \
		--proving-key $(ZK_PROVING_KEY) --output $(ZK_PROOF_FILE) \
		--public-inputs-out $(ZK_PUBLIC_INPUTS) --seed "nonos-boot-attestation-v1"
else
	$(ZK_CIRCUIT_DIR)/target/x86_64-unknown-linux-gnu/release/generate-proof \
		--proving-key $(ZK_PROVING_KEY) --output $(ZK_PROOF_FILE) \
		--public-inputs-out $(ZK_PUBLIC_INPUTS) --seed "nonos-boot-attestation-v1"
endif

embed-zk-proof: sign-kernel generate-zk-proof
	@echo "Embedding ZK proof into kernel..."
ifeq ($(UNAME_S),Darwin)
	cd $(BOOTLOADER_DIR)/tools/embed-zk-proof && $(CARGO) build --release --target x86_64-apple-darwin
	$(BOOTLOADER_DIR)/tools/embed-zk-proof/target/x86_64-apple-darwin/release/embed-zk-proof \
		--input $(TARGET_DIR)/kernel_signed.bin --output $(TARGET_DIR)/kernel_attested.bin \
		--proof $(ZK_PROOF_FILE) --program-hash $(ZK_PROGRAM_HASH) \
		--public-inputs $(ZK_PUBLIC_INPUTS) --verbose
else
	cd $(BOOTLOADER_DIR)/tools/embed-zk-proof && rm -rf target && RUSTFLAGS="" CARGO_UNSTABLE_BUILD_STD= $(CARGO) build --release --target x86_64-unknown-linux-gnu
	$(BOOTLOADER_DIR)/tools/embed-zk-proof/target/x86_64-unknown-linux-gnu/release/embed-zk-proof \
		--input $(TARGET_DIR)/kernel_signed.bin --output $(TARGET_DIR)/kernel_attested.bin \
		--proof $(ZK_PROOF_FILE) --program-hash $(ZK_PROGRAM_HASH) \
		--public-inputs $(ZK_PUBLIC_INPUTS) --verbose
endif

esp: bootloader kernel sign-kernel embed-zk-proof
	@echo "Building ESP..."
	@mkdir -p $(ESP_DIR)/EFI/Boot $(ESP_DIR)/EFI/nonos
	@cp $(BOOTLOADER_DIR)/target/x86_64-unknown-uefi/release/nonos_boot.efi $(ESP_DIR)/EFI/Boot/BOOTX64.EFI
	@cp $(TARGET_DIR)/kernel_attested.bin $(ESP_DIR)/EFI/nonos/kernel.bin
	@printf "timeout=0\ndefault=nonos\n" > $(ESP_DIR)/EFI/nonos/boot.cfg
	@echo 'fs0:\EFI\Boot\BOOTX64.EFI' > $(ESP_DIR)/startup.nsh

show-vk:
	@python3 -c "vk=open('$(ZK_VERIFYING_KEY)','rb').read(); \
		print('// VK:', len(vk), 'bytes'); \
		print('pub const VK_BOOT_AUTHORITY_BLS12_381_GROTH16: &[u8] = &['); \
		[print('    ' + ', '.join('0x{:02x}'.format(b) for b in vk[i:i+16]) + ',') for i in range(0,len(vk),16)]; \
		print('];')"

#
# Run targets
#

run: esp
	@echo "Booting NONOS... (Ctrl+A X to quit)"
	$(QEMU) -m 1G -cpu Haswell -machine q35 \
		-drive "format=raw,file=fat:rw:$(ESP_DIR)" \
		-drive if=pflash,format=raw,unit=0,readonly=on,file="$(OVMF)" \
		-drive if=pflash,format=raw,unit=1,readonly=on,file="$(OVMF_VARS)" \
		-device virtio-rng-pci -device e1000,netdev=net0 -netdev user,id=net0 \
		-serial mon:stdio -vga std -no-reboot

run-serial: esp
	$(QEMU) -m 1G -cpu Haswell -machine q35 \
		-drive "format=raw,file=fat:rw:$(ESP_DIR)" \
		-drive if=pflash,format=raw,readonly=on,file="$(OVMF)" \
		-device virtio-rng-pci -device e1000,netdev=net0 -netdev user,id=net0 \
		-serial mon:stdio -display none -no-reboot

debug: esp
	@echo "GDB server on :1234"
	$(QEMU) -m 1G -cpu Haswell -machine q35 \
		-drive "format=raw,file=fat:rw:$(ESP_DIR)" \
		-drive if=pflash,format=raw,readonly=on,file="$(OVMF)" \
		-device virtio-rng-pci -device e1000,netdev=net0 -netdev user,id=net0 \
		-serial mon:stdio -vga std -s -S -no-reboot

#
# Distribution
#

iso: esp
	@echo "Creating ISO..."
	@mkdir -p $(TARGET_DIR)/iso
	@cp -r $(ESP_DIR)/* $(TARGET_DIR)/iso/
ifeq ($(UNAME_S),Darwin)
	@command -v xorriso >/dev/null 2>&1 || brew install xorriso
	xorriso -as mkisofs -o $(TARGET_DIR)/nonos.iso -R -J -V "NONOS" \
		-e EFI/Boot/BOOTX64.EFI -no-emul-boot \
		-append_partition 2 0xef $(TARGET_DIR)/iso/EFI/Boot/BOOTX64.EFI \
		$(TARGET_DIR)/iso
else
	xorriso -as mkisofs -o $(TARGET_DIR)/nonos.iso -R -J -V "NONOS" \
		-e EFI/Boot/BOOTX64.EFI -no-emul-boot $(TARGET_DIR)/iso
endif
	@echo "Created: $(TARGET_DIR)/nonos.iso"

usb: esp
	@echo "Creating USB image..."
	@command -v sgdisk >/dev/null 2>&1 || { brew install gptfdisk 2>/dev/null || apt-get install -y gdisk; }
	@command -v mformat >/dev/null 2>&1 || { brew install mtools 2>/dev/null || apt-get install -y mtools; }
	@rm -f $(TARGET_DIR)/nonos.img $(TARGET_DIR)/esp.img
	$(eval ESP_SIZE_MB := $(shell echo $$(( ($$(du -sm $(ESP_DIR) | cut -f1) + 64 > 260) ? $$(du -sm $(ESP_DIR) | cut -f1) + 64 : 260 ))))
	$(eval DISK_SIZE_MB := $(shell echo $$(($(ESP_SIZE_MB) + 4))))
	dd if=/dev/zero of=$(TARGET_DIR)/nonos.img bs=1M count=$(DISK_SIZE_MB) status=none
	sgdisk --clear --new=1:2048:0 --typecode=1:EF00 --change-name=1:"EFI System Partition" $(TARGET_DIR)/nonos.img >/dev/null
	dd if=/dev/zero of=$(TARGET_DIR)/esp.img bs=1M count=$(ESP_SIZE_MB) status=none
	mformat -i $(TARGET_DIR)/esp.img -F -v EFI ::
	mmd -i $(TARGET_DIR)/esp.img ::/EFI
	mmd -i $(TARGET_DIR)/esp.img ::/EFI/Boot
	mmd -i $(TARGET_DIR)/esp.img ::/EFI/nonos
	mcopy -i $(TARGET_DIR)/esp.img $(ESP_DIR)/EFI/Boot/BOOTX64.EFI ::/EFI/Boot/
	mcopy -i $(TARGET_DIR)/esp.img $(ESP_DIR)/EFI/nonos/kernel.bin ::/EFI/nonos/
	mcopy -i $(TARGET_DIR)/esp.img $(ESP_DIR)/EFI/nonos/boot.cfg ::/EFI/nonos/
	@[ -f $(ESP_DIR)/startup.nsh ] && mcopy -i $(TARGET_DIR)/esp.img $(ESP_DIR)/startup.nsh ::/ || true
	dd if=$(TARGET_DIR)/esp.img of=$(TARGET_DIR)/nonos.img bs=1M seek=1 conv=notrunc status=none
	@rm -f $(TARGET_DIR)/esp.img
	@echo "Created: $(TARGET_DIR)/nonos.img"

#
# CI / Release
#

checksums:
	@mkdir -p $(RELEASE_DIR)
	@cp $(TARGET_DIR)/nonos.iso $(RELEASE_DIR)/nonos-$(VERSION).iso 2>/dev/null || true
	@cp $(TARGET_DIR)/nonos.img $(RELEASE_DIR)/nonos-$(VERSION).img 2>/dev/null || true
	@cp $(TARGET_DIR)/kernel_attested.bin $(RELEASE_DIR)/kernel-$(VERSION).bin 2>/dev/null || true
	@cd $(RELEASE_DIR) && sha256sum *.iso *.img *.bin 2>/dev/null > SHA256SUMS || shasum -a 256 *.iso *.img *.bin > SHA256SUMS
	@cat $(RELEASE_DIR)/SHA256SUMS

verify:
	@cd $(RELEASE_DIR) && sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS

ci-release: check-deps all iso usb checksums
	@echo "Release $(VERSION) complete"
	@ls -lh $(RELEASE_DIR)/

website-release: check-deps all iso usb
	@mkdir -p $(RELEASE_DIR)
	@cp $(TARGET_DIR)/nonos.iso $(RELEASE_DIR)/nonos-$(RELEASE_VERSION).iso
	@cp $(TARGET_DIR)/nonos.img $(RELEASE_DIR)/nonos-$(RELEASE_VERSION).img
	@cp $(TARGET_DIR)/kernel_attested.bin $(RELEASE_DIR)/nonos-kernel-$(RELEASE_VERSION).bin
	@cd $(RELEASE_DIR) && shasum -a 256 nonos-$(RELEASE_VERSION).* > SHA256SUMS.txt 2>/dev/null || sha256sum nonos-$(RELEASE_VERSION).* > SHA256SUMS.txt
	@cat $(RELEASE_DIR)/SHA256SUMS.txt

#
# Maintenance
#

clean:
	cd $(BOOTLOADER_DIR) && $(CARGO) clean 2>/dev/null || true
	$(CARGO) clean 2>/dev/null || true
	rm -rf $(TARGET_DIR)

distclean: clean
	rm -rf $(BOOTLOADER_DIR)/target target

test:
	$(CARGO) test --features std
	cd $(BOOTLOADER_DIR) && $(CARGO) test

fmt:
	$(CARGO) fmt
	cd $(BOOTLOADER_DIR) && $(CARGO) fmt

check:
	$(CARGO) clippy
	cd $(BOOTLOADER_DIR) && $(CARGO) clippy --target x86_64-unknown-uefi

help:
	@echo "NONOS Build System"
	@echo ""
	@echo "Build:       make, make bootloader, make kernel, make esp"
	@echo "Run:         make run, make run-serial, make debug"
	@echo "Distribute:  make iso, make usb"
	@echo "Release:     make ci-release, make website-release"
	@echo "ZK:          make zk-tools, make generate-zk-keys, make generate-zk-proof"
	@echo "Maintain:    make clean, make test, make fmt, make check"
	@echo ""
	@echo "Env: SIGNING_KEY (default: .keys/dev-signing.seed)"
