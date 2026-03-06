# NONOS Kernel Makefile
#
# Dev notes:
# - Uses nightly Rust (needs rust-src for build-std)
# - macOS: explicit toolchain paths avoid Homebrew's stable Rust shadowing nightly
# - ISO creation on non-Linux uses Docker (grub-mkrescue only works on Linux)
# - KVM enabled automatically on Linux if /dev/kvm exists
#
# Quick start:
#   make nonos-keygen-dev                    # generate dev signing key
#   export NONOS_SIGNING_KEY=$(pwd)/.keys/dev-signing.seed
#   make nonos                               # build release kernel
#   make nonos-run                           # boot in QEMU

.PHONY: all nonos nonos-debug nonos-run nonos-run-debug nonos-run-uefi nonos-debug-gdb
.PHONY: nonos-clean nonos-check nonos-clippy nonos-fmt nonos-test nonos-deps nonos-doc nonos-disasm
.PHONY: create-grub-iso create-uefi-disk iso iso-debug help nonos-help
.PHONY: nonos-keygen-dev nonos-keygen-prod nonos-key-fingerprint
.PHONY: build release run run-release debug clean check clippy fmt test deps doc disasm create-disk

# Paths
KERNEL_DIR := .
WORKSPACE_ROOT := $(shell cd $(KERNEL_DIR)/.. && pwd)
TARGET := x86_64-nonos
BUILD_DIR := $(WORKSPACE_ROOT)/target/$(TARGET)
RELEASE_DIR := $(BUILD_DIR)/release
DEBUG_DIR := $(BUILD_DIR)/debug
KERNEL_DIR_ABS := $(shell cd $(KERNEL_DIR) && pwd)

# Signing key (default to local dev key)
NONOS_SIGNING_KEY ?= $(KERNEL_DIR_ABS)/.keys/dev-signing.seed
export NONOS_SIGNING_KEY

# Host detection
HOST_OS := $(shell uname -s)
ifeq ($(HOST_OS),Darwin)
    IS_MACOS := 1
    STRIP := strip -x
    DOCKER := docker
else ifeq ($(HOST_OS),Linux)
    IS_LINUX := 1
    STRIP := strip --strip-all
else
    STRIP := strip
    DOCKER := docker
endif

# Rust toolchain - explicit paths to avoid Homebrew conflicts
export RUSTUP_TOOLCHAIN := nightly
ifdef IS_MACOS
    ARCH := $(shell uname -m)
    ifeq ($(ARCH),arm64)
        NIGHTLY_BIN := $(HOME)/.rustup/toolchains/nightly-aarch64-apple-darwin/bin
    else
        NIGHTLY_BIN := $(HOME)/.rustup/toolchains/nightly-x86_64-apple-darwin/bin
    endif
else
    NIGHTLY_BIN := $(HOME)/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin
endif

CARGO := $(NIGHTLY_BIN)/cargo
export RUSTC := $(NIGHTLY_BIN)/rustc
export RUSTDOC := $(NIGHTLY_BIN)/rustdoc

# Tools
QEMU := qemu-system-x86_64
GDB := gdb
OBJDUMP := objdump

# QEMU config
QEMU_ARGS := -machine q35 -m 512M -smp 2 -serial stdio \
	-device virtio-rng-pci \
	-device virtio-net-pci,netdev=net0 \
	-netdev user,id=net0
ifdef IS_MACOS
    QEMU_ARGS += -display cocoa
else
    QEMU_ARGS += -display gtk
endif
ifdef IS_LINUX
ifneq ($(wildcard /dev/kvm),)
    QEMU_ARGS += -enable-kvm -cpu host
endif
endif

# OVMF paths
ifdef IS_MACOS
    OVMF_CODE := /opt/homebrew/share/qemu/edk2-x86_64-code.fd
    OVMF_VARS := /opt/homebrew/share/qemu/edk2-i386-vars.fd
    ifeq ($(wildcard $(OVMF_CODE)),)
        OVMF_CODE := /usr/local/share/qemu/edk2-x86_64-code.fd
        OVMF_VARS := /usr/local/share/qemu/edk2-i386-vars.fd
    endif
else
    OVMF_CODE := /usr/share/OVMF/OVMF_CODE.fd
    OVMF_VARS := /usr/share/OVMF/OVMF_VARS.fd
endif

#
# Build
#

all: nonos

nonos:
	@echo "Building kernel (release)..."
	@test -n "$(NONOS_SIGNING_KEY)" || { echo "Set NONOS_SIGNING_KEY"; exit 1; }
	cd $(WORKSPACE_ROOT) && $(CARGO) build --release --package nonos_kernel \
		--target $(KERNEL_DIR_ABS)/$(TARGET).json -Zbuild-std=core,alloc -Zjson-target-spec
	@$(STRIP) $(RELEASE_DIR)/nonos_kernel 2>/dev/null || true
	@echo "Done: $(RELEASE_DIR)/nonos_kernel"

nonos-debug:
	@echo "Building kernel (debug)..."
	@test -n "$(NONOS_SIGNING_KEY)" || { echo "Set NONOS_SIGNING_KEY"; exit 1; }
	cd $(WORKSPACE_ROOT) && $(CARGO) build --package nonos_kernel \
		--target $(KERNEL_DIR_ABS)/$(TARGET).json -Zbuild-std=core,alloc -Zjson-target-spec
	@echo "Done: $(DEBUG_DIR)/nonos_kernel"

# Aliases
build: nonos-debug
release: nonos

#
# Run
#

nonos-run: nonos
	@$(MAKE) create-grub-iso KERNEL_PATH=$(RELEASE_DIR)/nonos_kernel
	$(QEMU) $(QEMU_ARGS) -cdrom build/nonos.iso

nonos-run-debug: nonos-debug
	@$(MAKE) create-grub-iso KERNEL_PATH=$(DEBUG_DIR)/nonos_kernel
	$(QEMU) $(QEMU_ARGS) -cdrom build/nonos.iso

nonos-run-uefi:
	@echo "UEFI boot disabled (bootloader conflicts). Use 'make nonos-run' instead."

nonos-debug-gdb: nonos-debug
	@echo "GDB server on :1234"
	@$(MAKE) create-grub-iso KERNEL_PATH=$(DEBUG_DIR)/nonos_kernel
	$(QEMU) $(QEMU_ARGS) -cdrom build/nonos.iso -s -S &
	@sleep 1
	$(GDB) $(DEBUG_DIR)/nonos_kernel -ex "target remote :1234" -ex "break _start" -ex "continue"

# Aliases
run: nonos-run-debug
run-release: nonos-run
debug: nonos-debug-gdb

#
# ISO
#

create-grub-iso:
	@echo "Creating GRUB ISO..."
	@mkdir -p build/isofiles/boot/grub
	@cp $(KERNEL_PATH) build/isofiles/boot/kernel.bin
	@printf 'set timeout=3\nset default=0\n\nmenuentry "NONOS Kernel" {\n    multiboot /boot/kernel.bin\n    boot\n}\n' \
		> build/isofiles/boot/grub/grub.cfg
ifdef IS_LINUX
	grub-mkrescue -o build/nonos.iso build/isofiles
else
	@echo "  (using Docker for grub-mkrescue)"
	$(DOCKER) run --rm -v "$(KERNEL_DIR_ABS)/build:/build" ubuntu:22.04 \
		sh -c "apt-get update -qq && apt-get install -qq -y grub-pc-bin grub-common xorriso mtools >/dev/null 2>&1 && grub-mkrescue -o /build/nonos.iso /build/isofiles"
endif
	@echo "Done: build/nonos.iso"

iso: nonos
	@$(MAKE) create-grub-iso KERNEL_PATH=$(RELEASE_DIR)/nonos_kernel

iso-debug: nonos-debug
	@$(MAKE) create-grub-iso KERNEL_PATH=$(DEBUG_DIR)/nonos_kernel

create-uefi-disk:
	@echo "UEFI disk creation disabled."

create-disk: create-grub-iso

#
# Development
#

nonos-check:
	cd $(WORKSPACE_ROOT) && $(CARGO) check --package nonos_kernel \
		--target $(KERNEL_DIR_ABS)/$(TARGET).json -Zbuild-std=core,alloc -Zjson-target-spec

nonos-clippy:
	cd $(WORKSPACE_ROOT) && $(CARGO) clippy --package nonos_kernel \
		--target $(KERNEL_DIR_ABS)/$(TARGET).json -Zbuild-std=core,alloc -Zjson-target-spec -- -W clippy::all

nonos-fmt:
	cd $(WORKSPACE_ROOT) && $(CARGO) fmt --all

nonos-test:
	cd $(WORKSPACE_ROOT) && $(CARGO) test --package nonos_kernel \
		--target $(KERNEL_DIR_ABS)/$(TARGET).json -Zbuild-std=core,alloc -Zjson-target-spec

nonos-deps:
	rustup component add rust-src llvm-tools-preview
	cargo install bootimage

nonos-doc:
	cd $(WORKSPACE_ROOT) && $(CARGO) doc --package nonos_kernel \
		--target $(KERNEL_DIR_ABS)/$(TARGET).json -Zbuild-std=core,alloc -Zjson-target-spec --open

nonos-disasm: nonos-debug
	@mkdir -p build
	$(OBJDUMP) -d $(DEBUG_DIR)/nonos_kernel > build/kernel.asm
	@echo "Done: build/kernel.asm"

# Aliases
check: nonos-check
clippy: nonos-clippy
fmt: nonos-fmt
test: nonos-test
deps: nonos-deps
doc: nonos-doc
disasm: nonos-disasm

#
# Cleanup
#

nonos-clean:
	cd $(WORKSPACE_ROOT) && $(CARGO) clean 2>/dev/null || true
	rm -rf build/

clean: nonos-clean

#
# Key management
#

nonos-keygen-dev:
	@mkdir -p .keys
	@dd if=/dev/urandom of=.keys/dev-signing.seed bs=32 count=1 2>/dev/null
	@chmod 600 .keys/dev-signing.seed
	@echo "Created: .keys/dev-signing.seed"
	@echo "export NONOS_SIGNING_KEY=\$$(pwd)/.keys/dev-signing.seed"

nonos-keygen-prod:
	@mkdir -p .keys
	@test ! -f .keys/prod-signing.seed || { echo "Key exists. Delete manually to regenerate."; exit 1; }
	@dd if=/dev/urandom of=.keys/prod-signing.seed bs=32 count=1 2>/dev/null
	@chmod 400 .keys/prod-signing.seed
	@echo "Created: .keys/prod-signing.seed (read-only)"
	@echo "Back this up. Loss = can't sign future releases."

nonos-key-fingerprint:
	@echo "Key fingerprints:"
	@test -f .keys/dev-signing.seed && printf "  dev:  " && shasum -a 256 .keys/dev-signing.seed | cut -c1-16 || true
	@test -f .keys/prod-signing.seed && printf "  prod: " && shasum -a 256 .keys/prod-signing.seed | cut -c1-16 || true

#
# Help
#

.DEFAULT_GOAL := nonos-help

nonos-help:
	@echo "NONOS Kernel Build"
	@echo ""
	@echo "Build:   make nonos, make nonos-debug"
	@echo "Run:     make nonos-run, make nonos-run-debug, make nonos-debug-gdb"
	@echo "ISO:     make iso, make iso-debug"
	@echo "Dev:     make nonos-check, make nonos-clippy, make nonos-fmt, make nonos-test"
	@echo "Setup:   make nonos-deps, make nonos-keygen-dev, make nonos-keygen-prod"
	@echo "Other:   make nonos-doc, make nonos-disasm, make nonos-clean"
	@echo ""
	@echo "Env: NONOS_SIGNING_KEY (default: .keys/dev-signing.seed)"
ifdef IS_MACOS
	@echo "Note: ISO creation uses Docker (grub-mkrescue needs Linux)"
endif
ifdef IS_LINUX
	@echo "Note: KVM enabled if /dev/kvm exists"
endif

help: nonos-help
