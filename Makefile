# -------------------------------
# NONOS Kernel-Only Makefile
# -------------------------------

# ---------- QEMU / OVMF ----------
QEMU_DIR   := $(shell brew --prefix qemu)/share/qemu
CODE_FD    := $(QEMU_DIR)/edk2-x86_64-code.fd
VARS_FD    := OVMF_VARS_rw.fd

# ---------- ESP paths ----------
ESP_DIR       := esp
ESP_BOOT_DIR  := $(ESP_DIR)/EFI/BOOT
EFI_BOOT      := $(ESP_BOOT_DIR)/BOOTX64.EFI      # kernel goes here
KERNEL_COPY   := $(ESP_DIR)/NONOS_KERNEL.EFI      # convenience copy

# ---------- Kernel (external repo or same tree) ----------
# If kernel & boot are the same repo, call:
#     make KERNEL_REPO=. run
KERNEL_REPO         ?= ../nonos-kernel
KERNEL_TARGET_JSON  ?= x86_64-nonos.json
KERNEL_TARGET_TRIPLE?=
KERNEL_PROFILE      ?= debug                 # debug | release

# Force errors on unset vars in recipes
.SHELLFLAGS := -o pipefail -c

.PHONY: all run kernel vars esp startup check-esp clean build

all: run

# -------------------------------
# Build-only (no staging, no QEMU)
# -------------------------------
build:
	@[ -d "$(KERNEL_REPO)" ] || { echo "Missing $(KERNEL_REPO). Set KERNEL_REPO to your kernel path."; exit 1; }
	@echo "==> Building kernel in $(KERNEL_REPO) ($(KERNEL_PROFILE))"
	@cd "$(KERNEL_REPO)" && { \
	  if [ -f "$(KERNEL_TARGET_JSON)" ]; then \
	    TARGET_FLAG="--target $(KERNEL_TARGET_JSON)"; \
	  else \
	    if [ -n "$(KERNEL_TARGET_TRIPLE)" ]; then \
	      TARGET_FLAG="--target $(KERNEL_TARGET_TRIPLE)"; \
	    else \
	      echo "ERROR: '$(KERNEL_TARGET_JSON)' not found and no KERNEL_TARGET_TRIPLE provided."; \
	      echo "       e.g. make KERNEL_TARGET_TRIPLE=x86_64-unknown-uefi build"; \
	      exit 1; \
	    fi; \
	  fi; \
	  if command -v jq >/dev/null 2>&1; then \
	    KPATH=$$(cargo build $$TARGET_FLAG $$(test "$(KERNEL_PROFILE)" = release && printf %s --release) --message-format=json \
	      | jq -r 'select(.executable!=null) | .executable' | tail -n1); \
	  else \
	    KPATH=$$(cargo build $$TARGET_FLAG $$(test "$(KERNEL_PROFILE)" = release && printf %s --release) --message-format=json \
	      | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n1); \
	  fi; \
	  [ -n "$$KPATH" ] && [ -f "$$KPATH" ] || { echo "ERROR: kernel binary not found (check build output)"; exit 1; }; \
	  echo "==> Built kernel EFI:"; echo "    $$KPATH"; \
	}

# -------------------------------
# Build kernel and stage into ESP
# -------------------------------
kernel:
	@[ -d "$(KERNEL_REPO)" ] || { echo "Missing $(KERNEL_REPO). Set KERNEL_REPO to your kernel path."; exit 1; }
	@echo "==> Building kernel in $(KERNEL_REPO) ($(KERNEL_PROFILE))"
	@cd "$(KERNEL_REPO)" && { \
	  if [ -f "$(KERNEL_TARGET_JSON)" ]; then \
	    TARGET_FLAG="--target $(KERNEL_TARGET_JSON)"; \
	  else \
	    if [ -n "$(KERNEL_TARGET_TRIPLE)" ]; then \
	      TARGET_FLAG="--target $(KERNEL_TARGET_TRIPLE)"; \
	    else \
	      echo "ERROR: '$(KERNEL_TARGET_JSON)' not found and no KERNEL_TARGET_TRIPLE provided."; \
	      echo "       e.g. make KERNEL_TARGET_TRIPLE=x86_64-unknown-uefi kernel"; \
	      exit 1; \
	    fi; \
	  fi; \
	  if command -v jq >/dev/null 2>&1; then \
	    KPATH=$$(cargo build $$TARGET_FLAG $$(test "$(KERNEL_PROFILE)" = release && printf %s --release) --message-format=json \
	      | jq -r 'select(.executable!=null) | .executable' | tail -n1); \
	  else \
	    KPATH=$$(cargo build $$TARGET_FLAG $$(test "$(KERNEL_PROFILE)" = release && printf %s --release) --message-format=json \
	      | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n1); \
	  fi; \
	  echo "    kernel EFI: $$KPATH"; \
	  [ -n "$$KPATH" ] && [ -f "$$KPATH" ] || { echo "ERROR: kernel binary not found (check build output)"; exit 1; }; \
	  mkdir -p "$(ESP_BOOT_DIR)"; \
	  cp -f "$$KPATH" "$(EFI_BOOT)"; \
	  cp -f "$$KPATH" "$(KERNEL_COPY)"; \
	}

# -------------------------------
# UEFI variables & ESP helpers
# -------------------------------
vars:
	@[ -f "$(CODE_FD)" ] || { echo "Missing $(CODE_FD). Install/reinstall qemu via Homebrew."; exit 1; }
	@[ -f "$(VARS_FD)" ] || qemu-img create -f raw "$(VARS_FD)" "$$(stat -f%z "$(CODE_FD)")"

startup:
	@mkdir -p "$(ESP_DIR)"
	@printf "%s\n" \
	  "echo NONOS startup.nsh launching..." \
	  "for %p in 0 1 2 3 4 5" \
	  "  if exist fs%p:\EFI\BOOT\BOOTX64.EFI then" \
	  "    fs%p:" \
	  "    \EFI\BOOT\BOOTX64.EFI" \
	  "    exit" \
	  "  endif" \
	  "endfor" \
	  "echo NONOS: BOOTX64.EFI not found on any fs*" \
	  > "$(ESP_DIR)/startup.nsh"

check-esp:
	@echo "==> ESP contents:"
	@find "$(ESP_DIR)" -maxdepth 4 -type f -print | sed 's/^/   /'

esp: kernel vars startup check-esp

# -------------------------------
# Run QEMU
# -------------------------------
run: esp
	qemu-system-x86_64 \
		-machine q35,accel=hvf -cpu host -m 1024 \
		-drive if=pflash,format=raw,readonly=on,file="$(CODE_FD)" \
		-drive if=pflash,format=raw,file="$(VARS_FD)" \
		-drive format=raw,file=fat:rw:$(ESP_DIR) \
		-serial stdio -monitor none -no-reboot

clean:
	rm -rf "$(ESP_DIR)" "$(VARS_FD)" target
