# NØNOS-Bootloader-Makefile
# UEFI bootloader build system

# Configuration
BOOT_DIR := .
TARGET := x86_64-unknown-uefi
BUILD_DIR := target/$(TARGET)
RELEASE_DIR := $(BUILD_DIR)/release
DEBUG_DIR := $(BUILD_DIR)/debug
ESP_DIR := target/esp
DIST_DIR := target/dist

# Tools
CARGO := cargo
OBJDUMP := objdump
OBJCOPY := objcopy
STRIP := strip
UPX := upx

# UEFI Configuration
EFI_ARCH := x64
BOOTLOADER_NAME := BOOTX64.EFI
KERNEL_NAME := nonos_kernel.efi

# Build flags
CARGO_FLAGS := --target $(TARGET)
CARGO_RELEASE_FLAGS := $(CARGO_FLAGS) --release
CARGO_DEV_FLAGS := $(CARGO_FLAGS)

# Features
FEATURES := default
RELEASE_FEATURES := $(FEATURES),zk-snark,efi-rng,nonos-cet
DEV_FEATURES := $(FEATURES),mock-proof

# Colors
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
RED := \033[0;31m
NC := \033[0m

# Tool directories
TOOLS_DIR := tools
TOOL_KEYGEN := $(TOOLS_DIR)/keygen
TOOL_SIGN := $(TOOLS_DIR)/sign-kernel
TOOL_THRESHOLD := $(TOOLS_DIR)/threshold-sign
TOOL_EMBED_ZK := $(TOOLS_DIR)/embed-zk-proof
TOOL_ZK_EMBED := $(TOOLS_DIR)/zk-embed
TOOL_CIRCUIT := $(TOOLS_DIR)/nonos-attestation-circuit

# Default target
.PHONY: all
all: build tools

# Check prerequisites
.PHONY: check-deps
check-deps:
	@echo -e "$(BLUE)Checking build dependencies...$(NC)"
	@command -v $(CARGO) >/dev/null 2>&1 || { echo -e "$(RED)Error: cargo not found$(NC)"; exit 1; }
	@rustup target list --installed | grep -q "$(TARGET)" || { \
		echo -e "$(YELLOW)Installing UEFI target...$(NC)"; \
		rustup target add $(TARGET); \
	}
	@echo -e "$(GREEN)✓ Dependencies satisfied$(NC)"

# Build development version
.PHONY: build dev
build dev: check-deps
	@echo -e "$(GREEN)Building NØNOS bootloader (development)...$(NC)"
	$(CARGO) build $(CARGO_DEV_FLAGS) --features "$(DEV_FEATURES)"
	@mkdir -p $(ESP_DIR)/EFI/BOOT
	@cp $(DEBUG_DIR)/nonos_boot.efi $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME)
	@echo -e "$(GREEN)✓ Development build complete$(NC)"

# Build release version
.PHONY: release
release: check-deps
	@echo -e "$(GREEN)Building NØNOS bootloader (release)...$(NC)"
	$(CARGO) build $(CARGO_RELEASE_FLAGS) --features "$(RELEASE_FEATURES)"
	@mkdir -p $(ESP_DIR)/EFI/BOOT
	@cp $(RELEASE_DIR)/nonos_boot.efi $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME)
	@echo -e "$(GREEN)✓ Release build complete$(NC)"

# Optimized production build
.PHONY: production prod
production prod: check-deps
	@echo -e "$(GREEN)Building NØNOS bootloader (production)...$(NC)"
	RUSTFLAGS="-C target-cpu=native -C link-arg=-s" \
	$(CARGO) build $(CARGO_RELEASE_FLAGS) --features "$(RELEASE_FEATURES)"
	@mkdir -p $(ESP_DIR)/EFI/BOOT $(DIST_DIR)
	@cp $(RELEASE_DIR)/nonos_boot.efi $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME)
	@if command -v $(STRIP) >/dev/null 2>&1; then \
		$(STRIP) $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME); \
		echo -e "$(GREEN)✓ Binary stripped$(NC)"; \
	fi
	@if command -v $(UPX) >/dev/null 2>&1; then \
		$(UPX) --best $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME) 2>/dev/null || true; \
		echo -e "$(GREEN)✓ Binary compressed$(NC)"; \
	fi
	@echo -e "$(GREEN)✓ Production build complete$(NC)"

# Build all signing and ZK tools
.PHONY: tools
tools: tools-keygen tools-sign tools-threshold tools-embed-zk tools-zk-embed tools-circuit
	@echo -e "$(GREEN)✓ All tools built$(NC)"

.PHONY: tools-keygen
tools-keygen:
	@echo -e "$(BLUE)Building keygen tool...$(NC)"
	cd $(TOOL_KEYGEN) && $(CARGO) build --release
	@echo -e "$(GREEN)✓ keygen built$(NC)"

.PHONY: tools-sign
tools-sign:
	@echo -e "$(BLUE)Building sign-kernel tool...$(NC)"
	cd $(TOOL_SIGN) && $(CARGO) build --release
	@echo -e "$(GREEN)✓ sign-kernel built$(NC)"

.PHONY: tools-threshold
tools-threshold:
	@echo -e "$(BLUE)Building threshold-sign tool...$(NC)"
	cd $(TOOL_THRESHOLD) && $(CARGO) build --release
	@echo -e "$(GREEN)✓ threshold-sign built$(NC)"

.PHONY: tools-embed-zk
tools-embed-zk:
	@echo -e "$(BLUE)Building embed-zk-proof tool...$(NC)"
	cd $(TOOL_EMBED_ZK) && $(CARGO) build --release
	@echo -e "$(GREEN)✓ embed-zk-proof built$(NC)"

.PHONY: tools-zk-embed
tools-zk-embed:
	@echo -e "$(BLUE)Building zk-embed tool...$(NC)"
	cd $(TOOL_ZK_EMBED) && $(CARGO) build --release
	@echo -e "$(GREEN)✓ zk-embed built$(NC)"

.PHONY: tools-circuit
tools-circuit:
	@echo -e "$(BLUE)Building attestation circuit...$(NC)"
	cd $(TOOL_CIRCUIT) && $(CARGO) build --release
	@echo -e "$(GREEN)✓ attestation-circuit built$(NC)"

# Fast incremental build
.PHONY: fast
fast:
	@echo -e "$(BLUE)Fast incremental build...$(NC)"
	$(CARGO) build $(CARGO_DEV_FLAGS) --features "$(DEV_FEATURES)"
	@mkdir -p $(ESP_DIR)/EFI/BOOT
	@cp $(DEBUG_DIR)/nonos_boot.efi $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME)

# Check code
.PHONY: check
check:
	@echo -e "$(BLUE)Checking code...$(NC)"
	$(CARGO) check $(CARGO_FLAGS) --features "$(FEATURES)"
	@echo -e "$(GREEN)✓ Code check complete$(NC)"

# Run clippy
.PHONY: clippy
clippy:
	@echo -e "$(BLUE)Running clippy...$(NC)"
	$(CARGO) clippy $(CARGO_FLAGS) --features "$(FEATURES)" -- -W clippy::all -W clippy::pedantic
	@echo -e "$(GREEN)✓ Clippy analysis complete$(NC)"

# Format code
.PHONY: fmt format
fmt format:
	@echo -e "$(BLUE)Formatting code...$(NC)"
	$(CARGO) fmt
	@echo -e "$(GREEN)✓ Code formatted$(NC)"

# Clean build artifacts
.PHONY: clean
clean:
	@echo -e "$(BLUE)Cleaning build artifacts...$(NC)"
	$(CARGO) clean
	rm -rf target/esp target/dist
	@echo -e "$(GREEN)✓ Clean complete$(NC)"

# Clean tools
.PHONY: tools-clean
tools-clean:
	@echo -e "$(BLUE)Cleaning tools...$(NC)"
	cd $(TOOL_KEYGEN) && $(CARGO) clean
	cd $(TOOL_SIGN) && $(CARGO) clean
	cd $(TOOL_THRESHOLD) && $(CARGO) clean
	cd $(TOOL_EMBED_ZK) && $(CARGO) clean
	cd $(TOOL_ZK_EMBED) && $(CARGO) clean
	cd $(TOOL_CIRCUIT) && $(CARGO) clean
	@echo -e "$(GREEN)✓ Tools cleaned$(NC)"

# Clean everything
.PHONY: clean-all
clean-all: clean tools-clean
	@echo -e "$(GREEN)✓ All cleaned$(NC)"

# Deep clean (including Cargo registry cache)
.PHONY: distclean
distclean: clean
	@echo -e "$(BLUE)Deep cleaning...$(NC)"
	rm -rf ~/.cargo/registry/cache ~/.cargo/git/db
	@echo -e "$(GREEN)✓ Deep clean complete$(NC)"

# Disassemble bootloader
.PHONY: disasm
disasm: build
	@echo -e "$(BLUE)Disassembling bootloader...$(NC)"
	@mkdir -p target/analysis
	$(OBJDUMP) -d $(DEBUG_DIR)/nonos_boot.efi > target/analysis/bootloader.asm
	@echo -e "$(GREEN)✓ Disassembly saved to target/analysis/bootloader.asm$(NC)"

# Analyze binary
.PHONY: analyze
analyze: build
	@echo -e "$(BLUE)Analyzing bootloader binary...$(NC)"
	@mkdir -p target/analysis
	@echo "=== Binary Information ===" > target/analysis/bootloader-info.txt
	@file $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME) >> target/analysis/bootloader-info.txt
	@echo "" >> target/analysis/bootloader-info.txt
	@echo "=== Size Information ===" >> target/analysis/bootloader-info.txt
	@ls -lh $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME) >> target/analysis/bootloader-info.txt
	@echo "" >> target/analysis/bootloader-info.txt
	@echo "=== Sections ===" >> target/analysis/bootloader-info.txt
	@$(OBJDUMP) -h $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME) >> target/analysis/bootloader-info.txt 2>/dev/null || true
	@echo -e "$(GREEN)✓ Analysis saved to target/analysis/bootloader-info.txt$(NC)"

# Create distribution package
.PHONY: dist
dist: production
	@echo -e "$(GREEN)Creating distribution package...$(NC)"
	@mkdir -p $(DIST_DIR)
	@cp -r $(ESP_DIR) $(DIST_DIR)/
	@cp README.md $(DIST_DIR)/ 2>/dev/null || true
	@echo "NØNOS UEFI Bootloader Distribution" > $(DIST_DIR)/README.txt
	@echo "=================================" >> $(DIST_DIR)/README.txt
	@echo "" >> $(DIST_DIR)/README.txt
	@echo "Built: $(shell date)" >> $(DIST_DIR)/README.txt
	@echo "Target: $(TARGET)" >> $(DIST_DIR)/README.txt
	@echo "Features: $(RELEASE_FEATURES)" >> $(DIST_DIR)/README.txt
	@echo "" >> $(DIST_DIR)/README.txt
	@echo "Installation:" >> $(DIST_DIR)/README.txt
	@echo "1. Copy esp/ contents to EFI System Partition" >> $(DIST_DIR)/README.txt
	@echo "2. Boot from UEFI firmware" >> $(DIST_DIR)/README.txt
	@cd $(DIST_DIR) && tar czf ../nonos-bootloader-$(shell date +%Y%m%d-%H%M%S).tar.gz .
	@echo -e "$(GREEN)✓ Distribution package created$(NC)"

# Install to ESP directory
.PHONY: install
install: release
	@echo -e "$(GREEN)Installing bootloader to ESP...$(NC)"
	@if [ -z "$(ESP_MOUNT)" ]; then \
		echo -e "$(RED)Error: ESP_MOUNT variable not set$(NC)"; \
		echo "Usage: make install ESP_MOUNT=/path/to/esp"; \
		exit 1; \
	fi
	@if [ ! -d "$(ESP_MOUNT)" ]; then \
		echo -e "$(RED)Error: $(ESP_MOUNT) is not a directory$(NC)"; \
		exit 1; \
	fi
	@mkdir -p "$(ESP_MOUNT)/EFI/BOOT"
	@cp $(ESP_DIR)/EFI/BOOT/$(BOOTLOADER_NAME) "$(ESP_MOUNT)/EFI/BOOT/"
	@echo -e "$(GREEN)✓ Bootloader installed to $(ESP_MOUNT)$(NC)"

# Development utilities
.PHONY: watch
watch:
	@echo -e "$(BLUE)Watching for changes...$(NC)"
	@command -v cargo-watch >/dev/null 2>&1 || { \
		echo -e "$(YELLOW)Installing cargo-watch...$(NC)"; \
		cargo install cargo-watch; \
	}
	cargo watch -x 'build --target $(TARGET) --features "$(DEV_FEATURES)"'

# Documentation
.PHONY: doc docs
doc docs:
	@echo -e "$(BLUE)Building documentation...$(NC)"
	$(CARGO) doc $(CARGO_FLAGS) --features "$(FEATURES)" --open

# Help
.PHONY: help
help:
	@echo "NØNOS UEFI Bootloader Build System"
	@echo "=================================="
	@echo ""
	@echo "Build targets:"
	@echo "  make all        - Build bootloader and all tools"
	@echo "  make build      - Build development version"
	@echo "  make release    - Build optimized release version"
	@echo "  make production - Build production version with all optimizations"
	@echo "  make fast       - Fast incremental development build"
	@echo ""
	@echo "Tools:"
	@echo "  make tools           - Build all signing and ZK tools"
	@echo "  make tools-keygen    - Build key generation tool"
	@echo "  make tools-sign      - Build kernel signing tool"
	@echo "  make tools-threshold - Build threshold signing tool (FROST)"
	@echo "  make tools-embed-zk  - Build ZK proof embedding tool"
	@echo "  make tools-zk-embed  - Build ZK embed tool"
	@echo "  make tools-circuit   - Build attestation circuit"
	@echo ""
	@echo "Quality assurance:"
	@echo "  make check      - Check code for errors"
	@echo "  make clippy     - Run clippy linter"
	@echo "  make fmt        - Format code"
	@echo ""
	@echo "Analysis:"
	@echo "  make disasm     - Disassemble bootloader binary"
	@echo "  make analyze    - Analyze binary structure"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make distclean  - Deep clean including caches"
	@echo ""
	@echo "Distribution:"
	@echo "  make dist       - Create distribution package"
	@echo "  make install    - Install to ESP (requires ESP_MOUNT=/path)"
	@echo ""
	@echo "Development:"
	@echo "  make watch      - Watch files and rebuild automatically"
	@echo "  make doc        - Build and open documentation"
	@echo ""
	@echo "Environment variables:"
	@echo "  ESP_MOUNT       - ESP mount point for installation"
	@echo "  FEATURES        - Cargo features to enable"

.DEFAULT_GOAL := help
