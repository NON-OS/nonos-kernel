<p align="center">
  <img src="assets/banner.png" alt="NØNOS ZeroState Bootloader" width="900">
</p>

<p align="center">
  <strong>Ed25519 Signatures</strong> · <strong>BLAKE3 Hashing</strong> · <strong>Groth16/BLS12-381 ZK Proofs</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#tools">Tools</a> •
  <a href="#security">Security</a>
</p>

---

## Overview

The ZeroState Bootloader is the cryptographic foundation of the NØNOS operating system. It runs before anything else, in the UEFI pre-boot environment and its sole purpose is to guarantee that only verified | attested code ever executes on the machine.

This is not a traditional bootloader that simply loads a kernel and jumps to it. By this Zero-State architecture the mission focus on a mathematically enforcment to a zero-trust architecture where every kernel binary must prove three things before it runs: that its code has not been tampered with, that it was signed by a trusted party and that it carries a valid zero-knowledge attestation proof. Miss any of these and the machine resets. There is no fallback, no recovery mode, no way around it. The most beautiful part is it belongs in the hands of every single operator, it seeks for privacy but removes the the assumptions where a person needs to trust what to run. 

The cryptography is real mostly likely is correct to say it will evolve with the future and needs, also by user feedbacks. An overview includes Ed25519 signatures using the dalek library. BLAKE3 hashing for integrity and key derivation. Groth16 zero-knowledge proofs over BLS12-381 via arkworks. Every comparison is constant-time. Every key derivation uses proper domain separation. This is production code, not a prototype anymore but moving to his challenges.

---

## Quick Start

### Prerequisites

> Rust nightly toolchain with UEFI target support

```
rustup install nightly
rustup target add x86_64-unknown-uefi
rustup component add rust-src
```

### Build Everything

> From the repository root directory

```
make all
```

This builds the bootloader, compiles the kernel, signs it with Ed25519, generates the ZK attestation proof and prepares the EFI System Partition.

### Run in QEMU

> Test the complete boot sequence

```
make run
```

For headless serial console output:

```
make run-serial
```

### Create Bootable ISO

> For deployment to real hardware

```
make iso
```

---

## How It Works

When you power on a machine running NØNOS, the UEFI firmware loads the bootloader from the EFI System Partition. The bootloader then executes ten stages in strict sequence.

### Boot Stages

| Stage | Name | Description |
|:-----:|------|-------------|
| 1 | UEFI Init | Initialize UEFI services and GOP framebuffer |
| 2 | Config | Load boot.toml configuration from ESP |
| 3 | Security | Enforce Secure Boot and TPM policies |
| 4 | Hardware | Enumerate ACPI tables, PCI bus, memory map |
| 5 | Load | Read kernel.bin from EFI/nonos/ |
| 6 | BLAKE3 | Compute integrity hash of kernel code |
| 7 | Ed25519 | Verify signature against trusted keystore |
| 8 | ZK Verify | Verify Groth16 attestation proof |
| 9 | ELF Parse | Parse and relocate kernel ELF64 |
| 10 | Handoff | Exit boot services, jump to kernel |

If any cryptographic verification fails, the bootloader triggers an immediate system reset. There is no way to bypass verification.

### Kernel Binary Format

The final attested kernel has three sections concatenated together:

```
# ELF Kernel Code | Variable size

# Key signature
Ed25519 Signature (64 bytes)

# ZK Proof Block to 272+ bytes
- Magic: 0x4E 0xC3 0x5A 0x50  
- Program Hash (32 bytes)      
- Capsule Commitment (32 bytes) 
- Public Inputs     
- Groth16 Proof (192 bytes)     
```

---

## The Signing Key

The signing key is the root of trust for the entire system. Whoever holds this key can sign kernels that the bootloader will accept.

### Key Location

> Place your 32-byte Ed25519 seed at:

```
keys/signing_key_v1.bin
```

Or set the environment variable:

```
export NONOS_SIGNING_KEY=/path/to/your/key.bin
```

### Key Derivation

At build time, the build system reads the 32-byte seed, derives the Ed25519 public key, and embeds it into the bootloader binary. It also computes a key ID using BLAKE3 with domain separation for revocation tracking.

### Generate New Keys

> Using the keygen tool

```
cd nonos-boot/tools/keygen
cargo run --release -- --count 1 --out-dir ../../../keys --allow-write-secrets
cp ../../../keys/signer1.key ../../../keys/signing_key_v1.bin
```

**Important:** Protect the signing key. Never commit it to version control. Store it encrypted or in an HSM for production use.

---

## Tools

Five command-line tools handle key management and kernel preparation.

### keygen

Generates Ed25519 signing keypairs with proper randomness and audit logging.

```
cd tools/keygen
cargo run --release -- \
  --count 4 \
  --threshold 3 \
  --out-dir ./keys \
  --signers signers.json \
  --allow-write-secrets
```

**Outputs:** Secret keys (mode 0600), public keys in multiple formats, signers.json manifest, generation_log.json with toolchain info and host fingerprint.

### sign-kernel

Signs a kernel binary with Ed25519, appending the 64-byte signature.

```
cd tools/sign-kernel
cargo run --release -- \
  --key ../../keys/signing_key_v1.bin \
  --input kernel.bin \
  --output kernel_signed.bin \
  --verify
```

### embed-zk-proof

Appends the ZK proof block to a signed kernel.

```
cd tools/embed-zk-proof
cargo run --release -- \
  --input kernel_signed.bin \
  --output kernel_attested.bin \
  --proof attestation_proof.bin \
  --program-id "nonos-boot-attest-v1" \
  --public-inputs public_inputs.bin
```

### zk-embed

Generates Rust constants for embedding verifying keys into the bootloader.

```
cd tools/zk-embed
cargo run --release -- \
  --program-id-str "nonos-boot-attest-v1" \
  --vk attestation_verifying_key.bin \
  --const-prefix BOOT_AUTHORITY
```

### nonos-attestation-circuit

Generates Groth16 proving and verifying keys, and creates attestation proofs.

```
cd tools/nonos-attestation-circuit

# Generate keys
cargo run --release --bin generate-keys -- generate \
  --output ./generated_keys \
  --print-program-hash

# Generate proof
cargo run --release --bin generate-proof -- \
  --proving-key ./generated_keys/attestation_proving_key.bin \
  --output proof.bin \
  --public-inputs-out public_inputs.bin
```

---

## Build Process

When you run `make all`, the following sequence executes:

| Step | Action |
|:----:|--------|
| 1 | Compile bootloader with zk-groth16 feature, embed signing key |
| 2 | Compile kernel for x86_64-nonos target |
| 3 | Sign kernel with Ed25519 using sign-kernel tool |
| 4 | Generate ZK attestation proof using proving key |
| 5 | Embed ZK proof block into signed kernel |
| 6 | Prepare ESP with bootloader and attested kernel |

### Make Targets

| Command | Description |
|---------|-------------|
| `make all` | Full build pipeline |
| `make bootloader` | Build bootloader only |
| `make kernel` | Build kernel only |
| `make sign-kernel` | Sign the kernel binary |
| `make embed-zk-proof` | Embed ZK proof into signed kernel |
| `make esp` | Prepare EFI System Partition |
| `make run` | Run in QEMU with display |
| `make run-serial` | Run in QEMU serial only |
| `make debug` | Run with GDB server |
| `make iso` | Create bootable ISO |
| `make clean` | Remove build artifacts |

---

## Security

### Cryptographic Primitives

| Component | Implementation |
|-----------|----------------|
| Signatures | Ed25519 via ed25519-dalek 2.1 |
| Hashing | BLAKE3-256 via blake3 1.5 |
| Key Derivation | BLAKE3 derive_key with domain separation |
| ZK Proofs | Groth16 via ark-groth16 0.4 |
| Pairing Curve | BLS12-381 via ark-bls12-381 0.4 |

### Domain Separators

All key derivation uses distinct domain strings to prevent cross-protocol attacks:

| Purpose | Domain String |
|---------|---------------|
| Key IDs | `NONOS:KEYID:ED25519:v1` |
| Program Hashes | `NONOS:ZK:PROGRAM:v1` |
| Commitments | `NONOS:CAPSULE:COMMITMENT:v1` |

### Security Properties

- **Constant-time comparisons** for all cryptographic values
- **Key versioning** with minimum version enforcement
- **Key revocation** by ID with reason codes and timestamps
- **Mandatory ZK attestation** — cannot be disabled
- **Optional buffer zeroization** via zk-zeroize feature

### Verification is Non-Negotiable

The bootloader has no bypass mechanism. A kernel missing a valid signature or ZK proof will not boot under any circumstances. The machine resets.

---

## Configuration

The bootloader reads `EFI/nonos/boot.toml` from the ESP if present.

```toml
[boot]
timeout = 0
default = "nonos"

[security]
require_secure_boot = false
require_tpm = false

[display]
show_log_panel = true
```

If the file is missing, defaults are used.

---

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| uefi | 0.23 | UEFI services |
| ed25519-dalek | 2.1 | Ed25519 signatures |
| blake3 | 1.5 | BLAKE3 hashing |
| ark-groth16 | 0.4 | Groth16 verifier |
| ark-bls12-381 | 0.4 | BLS12-381 curve |

All cryptographic code is pure Rust with no C dependencies.

---

## License

**AGPL-3.0-or-later**

Copyright 2026 NØNOS Contributors

---

<p align="center">
  <a href="https://nonos.systems">nonos.systems</a>
</p>
