# NONOS Kernel Build System
#
# Just run `make` to build everything, or `make run` to boot in QEMU.
# The build handles toolchain setup, key generation, and ZK proofs automatically.
#
# Quick reference:
#   make           - full build
#   make run       - boot in QEMU with networking
#   make run-vbox  - boot in VirtualBox
#   make iso       - create bootable ISO
#   make release   - clean + full signed/attested build + ISO + USB + checksums
#   make clean     - clean build artifacts
#
# For CI builds with custom signing key:
#   SIGNING_KEY=/path/to/key make ci-release
#
# Tested on macOS (arm64, x86_64) and Linux (x86_64).
# Pinned to nightly-2026-01-16 due to LLVM codegen regressions in newer nightlies.

.PHONY: all bootloader kernel esp run run-vbox vbox-create vbox-delete
.PHONY: run-serial debug iso usb clean distclean test fmt check help
.PHONY: check-deps setup-toolchain ensure-signing-key ensure-zk-keys
.PHONY: sign-kernel embed-zk-proof zk-tools ci-release checksums verify generate-zk-keys
.PHONY: release web-iso

# paths
BOOTLOADER_DIR := nonos-bootloader
TARGET_DIR := target
ESP_DIR := $(TARGET_DIR)/esp
RELEASE_DIR := $(TARGET_DIR)/release
KEYS_DIR := $(BOOTLOADER_DIR)/keys

# figure out what platform we're on
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# for reproducible builds
export SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date +%s)
export CARGO_INCREMENTAL := 0

# use rustup's cargo, not whatever brew installed
export PATH := $(HOME)/.cargo/bin:$(PATH)
TOOLCHAIN := nightly-2026-01-16
CARGO := $(HOME)/.cargo/bin/cargo
RUSTUP := $(HOME)/.cargo/bin/rustup

# platform-specific stuff
ifeq ($(UNAME_S),Darwin)
    ifeq ($(UNAME_M),arm64)
        HOST_TARGET := aarch64-apple-darwin
    else
        HOST_TARGET := x86_64-apple-darwin
    endif
    # need the Command Line Tools SDK for cross-compilation
    SDK_PATH := /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
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
    SDK_FLAGS :=
    SHA256 := sha256sum
else
    $(error Unsupported platform: $(UNAME_S))
endif

# signing key - gets generated if missing
SIGNING_KEY ?= $(KEYS_DIR)/signing_key_v1.bin

# zk attestation paths
ZK_CIRCUIT_DIR := $(BOOTLOADER_DIR)/tools/nonos-attestation-circuit
ZK_KEYS_DIR := $(ZK_CIRCUIT_DIR)/generated_keys
ZK_PROVING_KEY := $(ZK_KEYS_DIR)/attestation_proving_key.bin
ZK_VERIFYING_KEY := $(ZK_KEYS_DIR)/attestation_verifying_key.bin
ZK_KEY_SEED := nonos-production-attestation-v1-2026
ZK_TOOL := $(ZK_CIRCUIT_DIR)/target/$(HOST_TARGET)/release/generate-keys
EMBED_TOOL := $(BOOTLOADER_DIR)/tools/embed-zk-proof/target/$(HOST_TARGET)/release/embed-zk-proof

# qemu - check local firmware dir first, then system paths
ifeq ($(UNAME_S),Darwin)
    QEMU := qemu-system-x86_64
    OVMF := $(shell \
        if [ -f firmware/OVMF.fd ]; then echo firmware/OVMF.fd; \
        elif [ -f /opt/homebrew/share/qemu/edk2-x86_64-code.fd ]; then echo /opt/homebrew/share/qemu/edk2-x86_64-code.fd; \
        elif [ -f /usr/local/share/qemu/edk2-x86_64-code.fd ]; then echo /usr/local/share/qemu/edk2-x86_64-code.fd; \
        fi)
    OVMF_VARS := $(shell \
        if [ -f firmware/OVMF_VARS.fd ]; then echo firmware/OVMF_VARS.fd; \
        elif [ -f /opt/homebrew/share/qemu/edk2-i386-vars.fd ]; then echo /opt/homebrew/share/qemu/edk2-i386-vars.fd; \
        elif [ -f /usr/local/share/qemu/edk2-i386-vars.fd ]; then echo /usr/local/share/qemu/edk2-i386-vars.fd; \
        fi)
else
    QEMU := qemu-system-x86_64
    OVMF := $(shell test -f /usr/share/OVMF/OVMF_CODE.fd && echo /usr/share/OVMF/OVMF_CODE.fd || echo /usr/share/edk2/ovmf/OVMF_CODE.fd)
    OVMF_VARS := $(shell test -f /usr/share/OVMF/OVMF_VARS.fd && echo /usr/share/OVMF/OVMF_VARS.fd || echo /usr/share/edk2/ovmf/OVMF_VARS.fd)
endif

# virtualbox settings
VBOX_VM := NONOS
VBOX_ISO := $(TARGET_DIR)/nonos.iso
VBOX_RAM := 2048
VBOX_CPUS := 2
VBOX_VRAM := 128

# qemu hardware - virtio for speed, port forwarding for ssh/http
QEMU_MEM := 2G
QEMU_CPU := max
QEMU_SMP := 2
QEMU_NET := -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:80
QEMU_USB := -device qemu-xhci,id=xhci -device usb-tablet,bus=xhci.0
QEMU_RNG := -device virtio-rng-pci

# version from git
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
RELEASE_VERSION ?= 0.8.4


# default target
all: esp
	@echo ""
	@echo "Build complete: $(VERSION)"
	@echo ""
	@echo "  make run      - boot in QEMU (SSH on port 2222, HTTP on 8080)"
	@echo "  make run-vbox - boot in VirtualBox"
	@echo "  make iso      - create bootable ISO"
	@echo ""


# toolchain setup
setup-toolchain:
	@test -f $(RUSTUP) || { echo "rustup not found. Install from https://rustup.rs"; exit 1; }
	@echo "Checking toolchain $(TOOLCHAIN)..."
	@$(RUSTUP) toolchain install $(TOOLCHAIN) 2>/dev/null || true
	@$(RUSTUP) target add x86_64-unknown-uefi --toolchain $(TOOLCHAIN) 2>/dev/null || true
	@$(RUSTUP) component add rust-src clippy rustfmt --toolchain $(TOOLCHAIN) 2>/dev/null || true

check-deps: setup-toolchain

# signing key generation
$(SIGNING_KEY):
	@echo "Generating new signing key..."
	@mkdir -p $(KEYS_DIR)
	@head -c 32 /dev/urandom > $@
	@echo "Key saved to $@"

ensure-signing-key: $(SIGNING_KEY)

# zk tools
$(ZK_TOOL): check-deps
	@echo "Building ZK attestation tools..."
	@cd $(ZK_CIRCUIT_DIR) && RUSTFLAGS="" RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) build --release --bin generate-keys --bin generate-proof --target $(HOST_TARGET)

$(ZK_PROVING_KEY): $(ZK_TOOL)
	@echo "Running trusted setup for ZK circuit..."
	@mkdir -p $(ZK_KEYS_DIR)
	@$(ZK_TOOL) generate --output $(ZK_KEYS_DIR) --seed "$(ZK_KEY_SEED)" --allow-unsigned --print-program-hash
	@echo "Copying VK to expected circuit names..."
	@cp $(ZK_VERIFYING_KEY) $(ZK_KEYS_DIR)/vk_attestation_program.bin
	@cp $(ZK_VERIFYING_KEY) $(ZK_KEYS_DIR)/vk_boot_authority.bin
	@cp $(ZK_VERIFYING_KEY) $(ZK_KEYS_DIR)/vk_update_authority.bin
	@cp $(ZK_VERIFYING_KEY) $(ZK_KEYS_DIR)/vk_recovery_key.bin

$(ZK_VERIFYING_KEY): $(ZK_PROVING_KEY)

ensure-zk-keys: $(ZK_PROVING_KEY) $(ZK_VERIFYING_KEY)

generate-zk-keys: ensure-zk-keys

zk-tools: $(ZK_TOOL)

# embed tool
$(EMBED_TOOL): check-deps
	@echo "Building ZK embed tool..."
	@cd $(BOOTLOADER_DIR)/tools/embed-zk-proof && RUSTFLAGS="" RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) build --release --target $(HOST_TARGET)

# bootloader
$(BOOTLOADER_DIR)/target/x86_64-unknown-uefi/release/nonos_boot.efi: check-deps ensure-signing-key ensure-zk-keys
	@echo "Building UEFI bootloader..."
	$(eval SIGNING_KEY_ABS := $(if $(filter /%,$(SIGNING_KEY)),$(SIGNING_KEY),$(shell pwd)/$(SIGNING_KEY)))
	@cd $(BOOTLOADER_DIR) && \
		NONOS_SIGNING_KEY=$(SIGNING_KEY_ABS) \
		NONOS_ZK_CEREMONY_DIR=$(shell pwd)/$(ZK_KEYS_DIR) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --target x86_64-unknown-uefi --release --features zk-groth16

bootloader: $(BOOTLOADER_DIR)/target/x86_64-unknown-uefi/release/nonos_boot.efi

# kernel
$(TARGET_DIR)/x86_64-nonos/release/nonos-kernel: check-deps ensure-signing-key
	@echo "Building kernel..."
	$(eval SIGNING_KEY_ABS := $(if $(filter /%,$(SIGNING_KEY)),$(SIGNING_KEY),$(shell pwd)/$(SIGNING_KEY)))
	@$(SDK_FLAGS) NONOS_SIGNING_KEY=$(SIGNING_KEY_ABS) \
		RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \
		$(CARGO) build --release --target x86_64-nonos.json \
		-Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

kernel: $(TARGET_DIR)/x86_64-nonos/release/nonos-kernel

# signing
$(TARGET_DIR)/kernel_signed.bin: $(TARGET_DIR)/x86_64-nonos/release/nonos-kernel ensure-signing-key
	@echo "Signing kernel with Ed25519..."
	@mkdir -p $(TARGET_DIR)
ifeq ($(UNAME_S),Darwin)
	@/usr/bin/python3 scripts/sign_kernel.py $< $(SIGNING_KEY) $@
else
	@python3 scripts/sign_kernel.py $< $(SIGNING_KEY) $@
endif

sign-kernel: $(TARGET_DIR)/kernel_signed.bin

# zk embedding
$(TARGET_DIR)/kernel_attested.bin: $(TARGET_DIR)/kernel_signed.bin $(EMBED_TOOL) $(ZK_PROVING_KEY)
	@echo "Generating and embedding ZK attestation proof..."
	@$(EMBED_TOOL) --input $< --output $@ --proving-key $(ZK_PROVING_KEY) --seed "$(ZK_KEY_SEED)" --verbose

embed-zk-proof: $(TARGET_DIR)/kernel_attested.bin

# esp filesystem
esp: $(BOOTLOADER_DIR)/target/x86_64-unknown-uefi/release/nonos_boot.efi $(TARGET_DIR)/kernel_attested.bin
	@echo "Creating EFI System Partition..."
	@mkdir -p $(ESP_DIR)/EFI/Boot $(ESP_DIR)/EFI/nonos
	@cp $(BOOTLOADER_DIR)/target/x86_64-unknown-uefi/release/nonos_boot.efi $(ESP_DIR)/EFI/Boot/BOOTX64.EFI
	@cp $(TARGET_DIR)/kernel_attested.bin $(ESP_DIR)/EFI/nonos/kernel.bin
	@printf "timeout=0\ndefault=nonos\n" > $(ESP_DIR)/EFI/nonos/boot.cfg
	@echo 'fs0:\EFI\Boot\BOOTX64.EFI' > $(ESP_DIR)/startup.nsh
	@echo "ESP ready at $(ESP_DIR)"

# qemu
run: esp
	@echo "Booting NONOS in QEMU..."
	@echo "  SSH:  ssh -p 2222 localhost"
	@echo "  HTTP: http://localhost:8080"
	@echo "  Quit: Ctrl+A then X"
	@echo ""
	@$(QEMU) -m $(QEMU_MEM) -cpu $(QEMU_CPU) -smp $(QEMU_SMP) -machine q35 \
		-drive "format=raw,file=fat:rw:$(ESP_DIR)" \
		-drive if=pflash,format=raw,unit=0,readonly=on,file="$(OVMF)" \
		-drive if=pflash,format=raw,unit=1,readonly=on,file="$(OVMF_VARS)" \
		$(QEMU_NET) $(QEMU_USB) $(QEMU_RNG) \
		-serial mon:stdio -vga std -no-reboot

run-serial: esp
	@$(QEMU) -m $(QEMU_MEM) -cpu $(QEMU_CPU) -smp $(QEMU_SMP) -machine q35 \
		-drive "format=raw,file=fat:rw:$(ESP_DIR)" \
		-drive if=pflash,format=raw,readonly=on,file="$(OVMF)" \
		$(QEMU_NET) $(QEMU_RNG) \
		-serial mon:stdio -display none -no-reboot

debug: esp
	@echo "Starting QEMU with GDB server on port 1234..."
	@echo "Connect with: gdb -ex 'target remote :1234'"
	@$(QEMU) -m $(QEMU_MEM) -cpu $(QEMU_CPU) -smp $(QEMU_SMP) -machine q35 \
		-drive "format=raw,file=fat:rw:$(ESP_DIR)" \
		-drive if=pflash,format=raw,readonly=on,file="$(OVMF)" \
		$(QEMU_NET) $(QEMU_RNG) \
		-serial mon:stdio -vga std -s -S -no-reboot

# virtualbox - uses IMG (not ISO) because vbox efi doesn't boot custom ISOs well
vbox-create: usb
	@echo "Creating VirtualBox VM..."
	@VBoxManage controlvm "$(VBOX_VM)" poweroff 2>/dev/null || true
	@sleep 1
	@VBoxManage unregistervm "$(VBOX_VM)" --delete 2>/dev/null || true
	@VBoxManage closemedium disk "$(HOME)/VirtualBox VMs/$(VBOX_VM)/boot.vdi" --delete 2>/dev/null || true
	@rm -rf "$(HOME)/VirtualBox VMs/$(VBOX_VM)" $(TARGET_DIR)/nonos.vdi
	@VBoxManage convertfromraw $(TARGET_DIR)/nonos.img $(TARGET_DIR)/nonos.vdi --format VDI
	@VBoxManage createvm --name "$(VBOX_VM)" --ostype Other_64 --register
	@VBoxManage modifyvm "$(VBOX_VM)" --chipset ich9
	@VBoxManage modifyvm "$(VBOX_VM)" --firmware efi64
	@VBoxManage modifyvm "$(VBOX_VM)" --memory $(VBOX_RAM) --cpus $(VBOX_CPUS)
	@VBoxManage modifyvm "$(VBOX_VM)" --pae off --longmode on
	@VBoxManage modifyvm "$(VBOX_VM)" --hwvirtex on --nestedpaging on
	@VBoxManage modifyvm "$(VBOX_VM)" --apic on --x2apic on --ioapic on
	@VBoxManage modifyvm "$(VBOX_VM)" --vram $(VBOX_VRAM) --graphicscontroller vboxsvga
	@VBoxManage modifyvm "$(VBOX_VM)" --nic1 nat --nictype1 82545EM --natpf1 "ssh,tcp,,2222,,22"
	@VBoxManage modifyvm "$(VBOX_VM)" --usb on --usbxhci on
	@VBoxManage storagectl "$(VBOX_VM)" --name SATA --add sata --controller IntelAhci
	@mkdir -p "$(HOME)/VirtualBox VMs/$(VBOX_VM)"
	@mv $(TARGET_DIR)/nonos.vdi "$(HOME)/VirtualBox VMs/$(VBOX_VM)/boot.vdi"
	@VBoxManage storageattach "$(VBOX_VM)" --storagectl SATA --port 0 --device 0 --type hdd --medium "$(HOME)/VirtualBox VMs/$(VBOX_VM)/boot.vdi"
	@VBoxManage modifyvm "$(VBOX_VM)" --boot1 disk --boot2 none --boot3 none --boot4 none
	@echo ""
	@echo "VM '$(VBOX_VM)' created with:"
	@echo "  Chipset: ICH9 (Q35 equivalent)"
	@echo "  RAM:     $(VBOX_RAM) MB"
	@echo "  CPUs:    $(VBOX_CPUS)"
	@echo "  NIC:     Intel e1000 (NAT, SSH on port 2222)"
	@echo ""
	@echo "Run with: make run-vbox"

vbox-delete:
	@VBoxManage controlvm "$(VBOX_VM)" poweroff 2>/dev/null || true
	@sleep 1
	@VBoxManage unregistervm "$(VBOX_VM)" --delete 2>/dev/null || true
	@echo "VM '$(VBOX_VM)' deleted"

run-vbox: usb
	@VBoxManage showvminfo "$(VBOX_VM)" >/dev/null 2>&1 || $(MAKE) vbox-create
	@echo "Starting VirtualBox..."
	@VBoxManage startvm "$(VBOX_VM)"

# iso/usb creation
iso: esp
	@echo "Creating bootable ISO with embedded EFI..."
	@mkdir -p $(TARGET_DIR)/iso/EFI/Boot $(TARGET_DIR)/iso/EFI/nonos
	@cp $(ESP_DIR)/EFI/Boot/BOOTX64.EFI $(TARGET_DIR)/iso/EFI/Boot/
	@cp $(ESP_DIR)/EFI/nonos/kernel.bin $(TARGET_DIR)/iso/EFI/nonos/
	@cp $(ESP_DIR)/EFI/nonos/boot.cfg $(TARGET_DIR)/iso/EFI/nonos/
	@printf '@echo -off\nfor %%a run (0 9)\n  if exist fs%%a:\\EFI\\Boot\\BOOTX64.EFI then\n    fs%%a:\\EFI\\Boot\\BOOTX64.EFI\n    goto done\n  endif\nendfor\necho Boot not found\n:done\n' > $(TARGET_DIR)/iso/startup.nsh
ifeq ($(UNAME_S),Darwin)
	@command -v xorriso >/dev/null 2>&1 || { echo "Installing xorriso..."; brew install xorriso; }
	@command -v mformat >/dev/null 2>&1 || { echo "Installing mtools..."; brew install mtools; }
else ifeq ($(UNAME_S),Linux)
	@command -v xorriso >/dev/null 2>&1 || { echo "Install xorriso: sudo apt install xorriso"; exit 1; }
	@command -v mformat >/dev/null 2>&1 || { echo "Install mtools: sudo apt install mtools"; exit 1; }
endif
	@rm -f $(TARGET_DIR)/iso/efiboot.img
	@dd if=/dev/zero of=$(TARGET_DIR)/iso/efiboot.img bs=1M count=350 status=none
	@mformat -i $(TARGET_DIR)/iso/efiboot.img -F ::
	@mmd -i $(TARGET_DIR)/iso/efiboot.img ::/EFI ::/EFI/Boot ::/EFI/nonos
	@mcopy -i $(TARGET_DIR)/iso/efiboot.img $(TARGET_DIR)/iso/EFI/Boot/BOOTX64.EFI ::/EFI/Boot/
	@mcopy -i $(TARGET_DIR)/iso/efiboot.img $(TARGET_DIR)/iso/EFI/nonos/kernel.bin ::/EFI/nonos/
	@mcopy -i $(TARGET_DIR)/iso/efiboot.img $(TARGET_DIR)/iso/EFI/nonos/boot.cfg ::/EFI/nonos/
	@mcopy -i $(TARGET_DIR)/iso/efiboot.img $(TARGET_DIR)/iso/startup.nsh ::/
	@xorriso -as mkisofs -o $(TARGET_DIR)/nonos.iso -R -J -V "NONOS" \
		-eltorito-alt-boot -e efiboot.img -no-emul-boot -isohybrid-gpt-basdat \
		-append_partition 2 0xef $(TARGET_DIR)/iso/efiboot.img \
		$(TARGET_DIR)/iso
	@rm -f $(TARGET_DIR)/iso/efiboot.img
	@echo "ISO created: $(TARGET_DIR)/nonos.iso"

usb: esp
	@echo "Creating bootable USB image..."
ifeq ($(UNAME_S),Darwin)
	@command -v sgdisk >/dev/null 2>&1 || { echo "Installing gptfdisk..."; brew install gptfdisk; }
	@command -v mformat >/dev/null 2>&1 || { echo "Installing mtools..."; brew install mtools; }
else ifeq ($(UNAME_S),Linux)
	@command -v sgdisk >/dev/null 2>&1 || { echo "Install gdisk: sudo apt install gdisk"; exit 1; }
	@command -v mformat >/dev/null 2>&1 || { echo "Install mtools: sudo apt install mtools"; exit 1; }
endif
	@rm -f $(TARGET_DIR)/nonos.img $(TARGET_DIR)/esp.img
	@dd if=/dev/zero of=$(TARGET_DIR)/nonos.img bs=1M count=500 status=none
	@sgdisk --clear --new=1:2048:0 --typecode=1:EF00 --change-name=1:"ESP" $(TARGET_DIR)/nonos.img >/dev/null
	@dd if=/dev/zero of=$(TARGET_DIR)/esp.img bs=1M count=496 status=none
	@mformat -i $(TARGET_DIR)/esp.img -F -v EFI ::
	@mmd -i $(TARGET_DIR)/esp.img ::/EFI ::/EFI/Boot ::/EFI/nonos
	@mcopy -i $(TARGET_DIR)/esp.img $(ESP_DIR)/EFI/Boot/BOOTX64.EFI ::/EFI/Boot/
	@mcopy -i $(TARGET_DIR)/esp.img $(ESP_DIR)/EFI/nonos/kernel.bin ::/EFI/nonos/
	@mcopy -i $(TARGET_DIR)/esp.img $(ESP_DIR)/EFI/nonos/boot.cfg ::/EFI/nonos/
	@printf '@echo -off\nfor %%a run (0 9)\n  if exist fs%%a:\\EFI\\Boot\\BOOTX64.EFI then\n    fs%%a:\\EFI\\Boot\\BOOTX64.EFI\n    goto done\n  endif\nendfor\necho Boot not found\n:done\n' > $(TARGET_DIR)/startup_usb.nsh
	@mcopy -i $(TARGET_DIR)/esp.img $(TARGET_DIR)/startup_usb.nsh ::/startup.nsh
	@rm -f $(TARGET_DIR)/startup_usb.nsh
	@dd if=$(TARGET_DIR)/esp.img of=$(TARGET_DIR)/nonos.img bs=1M seek=1 conv=notrunc status=none
	@rm -f $(TARGET_DIR)/esp.img
	@echo "USB image created: $(TARGET_DIR)/nonos.img"
	@echo "Write with: sudo dd if=$(TARGET_DIR)/nonos.img of=/dev/sdX bs=4M status=progress"

# ci stuff
checksums:
	@mkdir -p $(RELEASE_DIR)
	@cp $(TARGET_DIR)/nonos.iso $(RELEASE_DIR)/nonos-$(VERSION).iso 2>/dev/null || true
	@cp $(TARGET_DIR)/nonos.img $(RELEASE_DIR)/nonos-$(VERSION).img 2>/dev/null || true
	@cp $(TARGET_DIR)/kernel_attested.bin $(RELEASE_DIR)/kernel-$(VERSION).bin 2>/dev/null || true
	@cd $(RELEASE_DIR) && $(SHA256) *.iso *.img *.bin > SHA256SUMS 2>/dev/null || true
	@echo "Checksums:"
	@cat $(RELEASE_DIR)/SHA256SUMS

verify:
	@cd $(RELEASE_DIR) && $(SHA256) -c SHA256SUMS

ci-release: all iso usb checksums
	@echo ""
	@echo "Release $(VERSION) ready:"
	@ls -lh $(RELEASE_DIR)/

release: clean all iso usb checksums
	@echo ""
	@echo "=== NONOS $(VERSION) Release Build Complete ==="
	@echo ""
	@echo "Artifacts:"
	@ls -lh $(RELEASE_DIR)/
	@echo ""
	@cat $(RELEASE_DIR)/SHA256SUMS
	@echo ""
	@echo "ISO: $(RELEASE_DIR)/nonos-$(VERSION).iso"
	@echo "IMG: $(RELEASE_DIR)/nonos-$(VERSION).img"

web-iso: iso
	@mkdir -p $(TARGET_DIR)/web
	@cp $(TARGET_DIR)/nonos.iso $(TARGET_DIR)/web/nonos.iso
	@$(SHA256) $(TARGET_DIR)/web/nonos.iso > $(TARGET_DIR)/web/nonos.iso.sha256
	@echo "Web ISO ready: $(TARGET_DIR)/web/nonos.iso"
	@cat $(TARGET_DIR)/web/nonos.iso.sha256

# cleanup
clean:
	@echo "Cleaning build artifacts..."
	@cd $(BOOTLOADER_DIR) && $(CARGO) clean 2>/dev/null || true
	@$(CARGO) clean 2>/dev/null || true
	@rm -rf $(TARGET_DIR)

distclean: clean
	@echo "Cleaning everything including keys..."
	@rm -rf $(BOOTLOADER_DIR)/target target
	@rm -f $(SIGNING_KEY)
	@rm -rf $(ZK_KEYS_DIR)

test:
	@RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) test --lib --features std --target $(HOST_TARGET)
	@cd $(BOOTLOADER_DIR) && RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) test

fmt:
	@RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) fmt
	@cd $(BOOTLOADER_DIR) && RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) fmt

check:
	@RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) clippy
	@cd $(BOOTLOADER_DIR) && RUSTUP_TOOLCHAIN=$(TOOLCHAIN) $(CARGO) clippy --target x86_64-unknown-uefi

help:
	@echo "NONOS Build System"
	@echo ""
	@echo "  make              build everything"
	@echo "  make run          boot in QEMU with networking"
	@echo "  make run-vbox     boot in VirtualBox"
	@echo "  make debug        boot with GDB server"
	@echo ""
	@echo "  make iso          create bootable ISO"
	@echo "  make usb          create bootable USB image"
	@echo "  make release      clean + full build + ISO + USB + checksums"
	@echo "  make web-iso      create ISO for web demo"
	@echo "  make ci-release   CI release build (no clean)"
	@echo ""
	@echo "  make clean        remove build artifacts"
	@echo "  make distclean    remove everything including keys"
	@echo "  make test         run tests"
	@echo "  make fmt          format code"
	@echo "  make check        run clippy"
	@echo ""
	@echo "Environment:"
	@echo "  SIGNING_KEY       path to Ed25519 signing key (default: auto-generated)"
	@echo "  VERSION           release version tag"
	@echo ""
	@echo "The build is fully automatic - just run 'make' and everything"
	@echo "will be set up, including toolchain, keys, and ZK proofs."
