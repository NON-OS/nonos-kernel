# Build Guide

How to build, test, and deploy the ZeroState bootloader.

---

## Prerequisites

- Rust nightly toolchain
- `x86_64-unknown-uefi` target
- QEMU with OVMF (for testing)

```bash
rustup toolchain install nightly
rustup target add x86_64-unknown-uefi
```

---

## Makefile Targets

### Core Build

```bash
make all          # Build bootloader + kernel + ESP (from root)
make bootloader   # Build UEFI bootloader only (cd .../nonos-bootloader && .....)
make kernel       # Build kernel only  (cd .../nonos-kernel && .....)
make esp          # Prepare EFI System Partition
```

### ZK Key Management

```bash
make zk-tools          # Build key generator and proof generator
make generate-zk-keys  # Generate new proving/verifying keys (trusted setup)
make generate-zk-proof # Generate attestation proof for kernel
make show-vk           # Display VK bytes for embedding in bootloader
```

The key generation uses seed `nonos-production-attestation-v1-2026` for deterministic, reproducible keys.

### Signing

```bash
make sign-kernel       # Sign kernel with Ed25519 key
make embed-zk-proof    # Embed ZK proof into kernel binary
```

### Run Targets

```bash
make run          # Run in QEMU with graphical display
make run-serial   # Run in QEMU headless (serial only)
make debug        # Run with GDB server enabled
```

### Distribution

```bash
make iso          # Create bootable ISO image
```

### Maintenance

```bash
make clean        # Remove build artifacts
make distclean    # Deep clean including dependencies
make test         # Run kernel and bootloader tests
make fmt          # Format code with rustfmt
make check        # Run clippy lints
make help         # Show all available targets
```

---

## Full build pipeline

The complete pipeline for a production build:

```bash
# 1. Build tools
make zk-tools

# 2. Generate ZK keys (only needed once per circuit version)
make generate-zk-keys

# 3. Embed VK in bootloader (update keys.rs if needed)
make show-vk  # Copy output to src/zk/registry/keys.rs

# 4. Build bootloader and kernel
make bootloader kernel

# 5. Sign and attest kernel
make sign-kernel generate-zk-proof embed-zk-proof

# 6. Prepare ESP and run
make esp run
```

Or simply:

```bash
make run  # Does everything
```

---

## Build Reproducibility

For reproducible builds, control these variables:

| Variable | Purpose |
|----------|---------|
| `BUILD_TIMESTAMP` | Set to fixed value |
| `ZK_KEY_SEED` | Deterministic key generation |
| Toolchain version | Pin rustc version exactly |
| `Cargo.lock` | Lock dependency versions |

For bit-for-bit reproducible builds, use a containerized environment with all variables locked down.

---

## Key Files

| Path | Purpose |
|------|---------|
| `nonos-boot/tools/nonos-attestation-circuit/generated_keys/attestation_proving_key.bin` | Proving key (~979KB) |
| `nonos-boot/tools/nonos-attestation-circuit/generated_keys/attestation_verifying_key.bin` | Verifying key (584 bytes) |
| `nonos-boot/src/zk/registry/keys.rs` | Embedded VK bytes |
| `target/x86_64-unknown-uefi/release/nonos-boot.efi` | Built bootloader |
| `target/x86_64-nonos/release/nonos-kernel` | Built kernel |

---

## Kernel Updates (Production)

1. Build new kernel
2. Sign with `sign-kernel` using signing key
3. Generate proof with `generate-proof` using proving key
4. Embed proof with `embed-zk-proof`
5. Deploy to ESP

Typically automated in CI. Signing key and proving key live in secure storage (HSM, vault). Build system accesses them, humans don't touch them directly.

---

## Custom Targets

### x86_64-nonos

Custom target triple for the kernel:
- no_std (no standard library)
- No dynamic linking
- Custom linker script for kernel memory layout
- Specific ABI for kernel entry

This is how you build a freestanding kernel. The ZK circuit doesn't know or care about target triples.

---

## Troubleshooting

**Build fails with missing target:**
```bash
rustup target add x86_64-unknown-uefi
```

**QEMU fails to start:**
Ensure OVMF is installed and the path in Makefile is correct.

**ZK key generation fails:**
Check that arkworks dependencies are building correctly. May need nightly Rust.

**Proof verification fails at boot:**
1. Check VK in bootloader matches generated VK
2. Check program hash matches between circuit and bootloader
3. Regenerate keys if circuit was modified
