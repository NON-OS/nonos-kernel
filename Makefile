# NØNOS Kernel Makefile

# Configuration
KERNEL_DIR := .
TARGET := x86_64-nonos
BUILD_DIR := $(KERNEL_DIR)/target/$(TARGET)
RELEASE_DIR := $(BUILD_DIR)/release
DEBUG_DIR := $(BUILD_DIR)/debug

# Signing key (required for build)
NONOS_SIGNING_KEY ?= /home/nonos/nonos-kernel/.keys/signing.seed

# Tools
CARGO := cargo
QEMU := qemu-system-x86_64
GDB := gdb
OBJDUMP := objdump
OBJCOPY := objcopy

# QEMU configuration
QEMU_ARGS := -machine q35 \
             -m 512M \
             -smp 2 \
             -serial stdio \
             -display gtk

# Check for KVM support
ifneq ($(wildcard /dev/kvm),)
    QEMU_ARGS += -enable-kvm -cpu host
endif

# OVMF UEFI firmware
OVMF_CODE := /usr/share/OVMF/OVMF_CODE.fd
OVMF_VARS := /usr/share/OVMF/OVMF_VARS.fd

# Environment setup
export NONOS_SIGNING_KEY

# Default target
.PHONY: all
all: nonos

# NØNOS Build targets
.PHONY: nonos
nonos:
	@echo "Building NØNOS kernel (release)..."
	@if [ -z "$(NONOS_SIGNING_KEY)" ]; then \
		echo "Error: NONOS_SIGNING_KEY environment variable is required"; \
		echo "Usage: export NONOS_SIGNING_KEY=/path/to/signing.seed"; \
		exit 1; \
	fi
	cd $(KERNEL_DIR) && $(CARGO) build --release --target $(TARGET).json -Zbuild-std=core,alloc
	@strip --strip-all target/$(TARGET)/release/nonos_kernel 2>/dev/null || true
	@echo "NØNOS kernel build complete!"

.PHONY: nonos-debug
nonos-debug:
	@echo "Building NØNOS kernel (debug)..."
	@if [ -z "$(NONOS_SIGNING_KEY)" ]; then \
		echo "Error: NONOS_SIGNING_KEY environment variable is required"; \
		echo "Usage: export NONOS_SIGNING_KEY=/path/to/signing.seed"; \
		exit 1; \
	fi
	cd $(KERNEL_DIR) && $(CARGO) build --target $(TARGET).json -Zbuild-std=core,alloc
	@echo "NØNOS kernel debug build complete!"

# Legacy aliases (deprecated)
.PHONY: build release
build: nonos-debug
release: nonos

# NØNOS Run targets
.PHONY: nonos-run
nonos-run: nonos
	@echo "Running NØNOS in QEMU (GRUB)..."
	@$(MAKE) create-grub-iso KERNEL_PATH=$(RELEASE_DIR)/nonos_kernel
	$(QEMU) $(QEMU_ARGS) -cdrom build/nonos.iso

.PHONY: nonos-run-debug
nonos-run-debug: nonos-debug
	@echo "Running NØNOS (debug) in QEMU..."
	@$(MAKE) create-grub-iso KERNEL_PATH=$(DEBUG_DIR)/nonos_kernel
	$(QEMU) $(QEMU_ARGS) -cdrom build/nonos.iso

.PHONY: nonos-run-uefi
nonos-run-uefi: nonos
	@echo "Running NØNOS in QEMU (UEFI - DISABLED)..."
	@echo "UEFI boot is disabled - bootloader conflicts with UEFI firmware"
	@echo "Use 'make nonos-run' for GRUB multiboot instead"

.PHONY: nonos-debug-gdb
nonos-debug-gdb: nonos-debug
	@echo "Starting NØNOS with GDB server..."
	@$(MAKE) create-grub-iso KERNEL_PATH=$(DEBUG_DIR)/nonos_kernel
	$(QEMU) $(QEMU_ARGS) -cdrom build/nonos.iso -s -S &
	@echo "QEMU started. Connect with GDB using: target remote :1234"
	$(GDB) $(DEBUG_DIR)/nonos_kernel \
	       -ex "target remote :1234" \
	       -ex "break _start" \
	       -ex "continue"

# Clean build artifacts
.PHONY: nonos-clean
nonos-clean:
	@echo "Cleaning NØNOS build artifacts..."
	cd $(KERNEL_DIR) && $(CARGO) clean
	rm -rf build/
	@echo "NØNOS clean complete!"

# Legacy aliases (deprecated)
.PHONY: run run-release debug clean
run: nonos-run-debug
run-release: nonos-run
debug: nonos-debug-gdb
clean: nonos-clean

# Create GRUB bootable ISO
.PHONY: create-grub-iso
create-grub-iso:
	@echo "Creating GRUB ISO image..."
	@mkdir -p build/isofiles/boot/grub
	@cp $(KERNEL_PATH) build/isofiles/boot/kernel.bin
	@echo 'menuentry "NONOS Kernel" {' > build/isofiles/boot/grub/grub.cfg
	@echo '    multiboot /boot/kernel.bin' >> build/isofiles/boot/grub/grub.cfg
	@echo '    boot' >> build/isofiles/boot/grub/grub.cfg
	@echo '}' >> build/isofiles/boot/grub/grub.cfg
	grub-mkrescue -o build/nonos.iso build/isofiles
	@echo "GRUB ISO created!"

# Create UEFI disk image (disabled)
.PHONY: create-uefi-disk
create-uefi-disk:
	@echo "Creating UEFI disk image (disabled)..."
	@mkdir -p build
	@cp $(OVMF_VARS) build/OVMF_VARS.fd
	@dd if=/dev/zero of=build/nonos.img bs=1M count=64 2>/dev/null
	@mkfs.vfat build/nonos.img
	@echo "UEFI disk image created (not functional)!"

# Legacy disk creation
.PHONY: create-disk
create-disk: create-grub-iso

# Disassemble kernel
.PHONY: disasm
disasm: build
	@echo "Disassembling kernel..."
	$(OBJDUMP) -d $(DEBUG_DIR)/nonos_kernel > build/kernel.asm
	@echo "Disassembly saved to build/kernel.asm"

# NØNOS Development targets
.PHONY: nonos-check
nonos-check:
	@echo "Checking NØNOS code..."
	cd $(KERNEL_DIR) && $(CARGO) check --target $(TARGET).json -Zbuild-std=core,alloc

.PHONY: nonos-clippy
nonos-clippy:
	@echo "Running clippy on NØNOS..."
	cd $(KERNEL_DIR) && $(CARGO) clippy --target $(TARGET).json -Zbuild-std=core,alloc -- -W clippy::all

.PHONY: nonos-fmt
nonos-fmt:
	@echo "Formatting NØNOS code..."
	cd $(KERNEL_DIR) && $(CARGO) fmt

.PHONY: nonos-test
nonos-test:
	@echo "Running NØNOS tests..."
	cd $(KERNEL_DIR) && $(CARGO) test --target $(TARGET).json -Zbuild-std=core,alloc

# Legacy aliases (deprecated)
.PHONY: check clippy fmt test
check: nonos-check
clippy: nonos-clippy
fmt: nonos-fmt
test: nonos-test

# NØNOS Setup targets
.PHONY: nonos-deps
nonos-deps:
	@echo "Installing NØNOS dependencies..."
	rustup component add rust-src
	rustup component add llvm-tools-preview
	cargo install bootimage
	@echo "NØNOS dependencies installed!"

.PHONY: nonos-doc
nonos-doc:
	@echo "Building NØNOS documentation..."
	cd $(KERNEL_DIR) && $(CARGO) doc --target $(TARGET).json --open

.PHONY: nonos-disasm
nonos-disasm: nonos-debug
	@echo "Disassembling NØNOS kernel..."
	$(OBJDUMP) -d $(DEBUG_DIR)/nonos_kernel > build/kernel.asm
	@echo "Disassembly saved to build/kernel.asm"

# Legacy aliases (deprecated)
.PHONY: deps doc disasm
deps: nonos-deps
doc: nonos-doc
disasm: nonos-disasm

# Help
.PHONY: nonos-help
nonos-help:
	@echo "NØNOS Kernel Build System"
	@echo ""
	@echo "Main NØNOS targets:"
	@echo "  make nonos             - Build NØNOS kernel (release)"
	@echo "  make nonos-debug       - Build NØNOS kernel (debug)"
	@echo "  make nonos-run         - Run NØNOS in QEMU (release)"
	@echo "  make nonos-run-debug   - Run NØNOS in QEMU (debug)"
	@echo "  make nonos-debug-gdb   - Run NØNOS with GDB debugger"
	@echo "  make nonos-clean       - Clean NØNOS build artifacts"
	@echo ""
	@echo "Development targets:"
	@echo "  make nonos-check       - Check NØNOS code for errors"
	@echo "  make nonos-clippy      - Run clippy linter on NØNOS"
	@echo "  make nonos-fmt         - Format NØNOS code"
	@echo "  make nonos-test        - Run NØNOS tests"
	@echo "  make nonos-doc         - Build and open NØNOS documentation"
	@echo "  make nonos-disasm      - Disassemble NØNOS kernel"
	@echo "  make nonos-deps        - Install NØNOS dependencies"
	@echo ""
	@echo "Environment:"
	@echo "  NONOS_SIGNING_KEY      - Path to signing key (required)"
	@echo ""
	@echo "Legacy aliases (deprecated):"
	@echo "  make build, release, run, debug, clean, check, clippy, fmt, test"

.PHONY: help
help: nonos-help

.DEFAULT_GOAL := nonos-help
