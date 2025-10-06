# NØNOS Kernel Makefile

# Configuration
KERNEL_DIR := .
TARGET := x86_64-nonos
BUILD_DIR := $(KERNEL_DIR)/target/$(TARGET)
RELEASE_DIR := $(BUILD_DIR)/release
DEBUG_DIR := $(BUILD_DIR)/debug

# Tools
CARGO := cargo
QEMU := qemu-system-x86_64
GDB := gdb
OBJDUMP := objdump
OBJCOPY := objcopy

# QEMU configuration - base args
QEMU_ARGS := -machine q35 \
             -m 512M \
             -smp 2 \
             -serial stdio

# Check for KVM support (Linux only) and set display
ifeq ($(UNAME_S),Linux)
    ifneq ($(wildcard /dev/kvm),)
        QEMU_ARGS += -enable-kvm -cpu host
    endif
    QEMU_ARGS += -display gtk
else ifeq ($(UNAME_S),Darwin)
    # macOS: Use hvf (Hypervisor.framework) if available
    QEMU_ARGS += -accel hvf -cpu max
    # Use cocoa display on macOS (default), or sdl if preferred
    QEMU_ARGS += -display cocoa
endif

# OVMF UEFI firmware
# Detect OS and set appropriate paths
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS paths (Homebrew QEMU)
    QEMU_SHARE := $(shell brew --prefix qemu)/share/qemu
    OVMF_CODE := $(QEMU_SHARE)/edk2-x86_64-code.fd
    OVMF_VARS := $(QEMU_SHARE)/edk2-i386-vars.fd
else
    # Linux paths
    OVMF_CODE := /usr/share/OVMF/OVMF_CODE.fd
    OVMF_VARS := /usr/share/OVMF/OVMF_VARS.fd
endif

# Default target
.PHONY: all
all: build

# Build targets
.PHONY: build
build:
	@echo "Building NØNOS kernel..."
	cd $(KERNEL_DIR) && $(CARGO) build --target $(TARGET).json
	@echo "Build complete!"

.PHONY: release
release:
	@echo "Building NØNOS kernel (release)..."
	cd $(KERNEL_DIR) && $(CARGO) build --release --target $(TARGET).json
	@echo "Release build complete!"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	cd $(KERNEL_DIR) && $(CARGO) clean
	rm -rf build/
	@echo "Clean complete!"

# Run in QEMU
.PHONY: run
run: build
	@echo "Running NØNOS in QEMU..."
	@mkdir -p build/esp/EFI/BOOT
	@cp $(DEBUG_DIR)/nonos_kernel build/esp/kernel.bin
	@$(MAKE) create-disk
	$(QEMU) $(QEMU_ARGS) \
	        -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	        -drive if=pflash,format=raw,file=build/OVMF_VARS.fd \
	        -drive format=raw,file=build/nonos.img

.PHONY: run-release
run-release: release
	@echo "Running NØNOS (release) in QEMU..."
	@mkdir -p build/esp/EFI/BOOT
	@cp $(RELEASE_DIR)/nonos_kernel build/esp/kernel.bin
	@$(MAKE) create-disk
	$(QEMU) $(QEMU_ARGS) \
	        -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	        -drive if=pflash,format=raw,file=build/OVMF_VARS.fd \
	        -drive format=raw,file=build/nonos.img

# Debug with GDB
.PHONY: debug
debug: build
	@echo "Starting QEMU with GDB server..."
	@mkdir -p build/esp/EFI/BOOT
	@cp $(DEBUG_DIR)/nonos_kernel build/esp/kernel.bin
	@$(MAKE) create-disk
	$(QEMU) $(QEMU_ARGS) \
	        -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	        -drive if=pflash,format=raw,file=build/OVMF_VARS.fd \
	        -drive format=raw,file=build/nonos.img \
	        -s -S &
	@echo "QEMU started. Connect with GDB using: target remote :1234"
	$(GDB) $(DEBUG_DIR)/nonos_kernel \
	       -ex "target remote :1234" \
	       -ex "break _start" \
	       -ex "continue"

# Create disk image
.PHONY: create-disk
create-disk:
	@echo "Creating disk image..."
	@mkdir -p build
	@cp $(OVMF_VARS) build/OVMF_VARS.fd
	@dd if=/dev/zero of=build/nonos.img bs=1M count=64 2>/dev/null
ifeq ($(UNAME_S),Linux)
	@mkfs.vfat build/nonos.img > /dev/null 2>&1
endif
	@echo "Disk image created!"

# Disassemble kernel
.PHONY: disasm
disasm: build
	@echo "Disassembling kernel..."
	$(OBJDUMP) -d $(DEBUG_DIR)/nonos_kernel > build/kernel.asm
	@echo "Disassembly saved to build/kernel.asm"

# Check code
.PHONY: check
check:
	@echo "Checking code..."
	cd $(KERNEL_DIR) && $(CARGO) check --target $(TARGET).json

# Run clippy
.PHONY: clippy
clippy:
	@echo "Running clippy..."
	cd $(KERNEL_DIR) && $(CARGO) clippy --target $(TARGET).json -- -W clippy::all

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	cd $(KERNEL_DIR) && $(CARGO) fmt

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	cd $(KERNEL_DIR) && $(CARGO) test --target $(TARGET).json

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	rustup component add rust-src
	rustup component add llvm-tools-preview
	cargo install bootimage
	@echo "Dependencies installed!"

# Documentation
.PHONY: doc
doc:
	@echo "Building documentation..."
	cd $(KERNEL_DIR) && $(CARGO) doc --target $(TARGET).json --open

# Help
.PHONY: help
help:
	@echo "NØNOS Kernel Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  make build        - Build kernel (debug)"
	@echo "  make release      - Build kernel (release)"
	@echo "  make run          - Run kernel in QEMU"
	@echo "  make run-release  - Run release build in QEMU"
	@echo "  make debug        - Run with GDB debugger"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make check        - Check code for errors"
	@echo "  make clippy       - Run clippy linter"
	@echo "  make fmt          - Format code"
	@echo "  make test         - Run tests"
	@echo "  make doc          - Build and open documentation"
	@echo "  make disasm       - Disassemble kernel"
	@echo "  make deps         - Install dependencies"
	@echo "  make help         - Show this help"

.DEFAULT_GOAL := help
