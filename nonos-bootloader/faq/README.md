```
##    ##   ######   ##    ##   ######    ######
###   ##  ##    ##  ###   ##  ##    ##  ##    ##
####  ##  ##    ##  ####  ##  ##    ##  ##
## ## ##  ##    ##  ## ## ##  ##    ##   ######
##  ####  ##    ##  ##  ####  ##    ##        ##
##   ###  ##    ##  ##   ###  ##    ##  ##    ##
 ##    ##   ######   ##    ##   ######    ######

```

# ZeroState Bootloader Documentation

Honest documentation about what this bootloader does, how it works and what its limitations are.

---

## Release Status

**Cryptographic implementation**: Ed25519 signatures, Groth16 proofs, BLAKE3 integrity verification. The code does what it claims.

**Ecosystem maturity**: Early. Limited hardware testing beyond QEMU. !*No third-party security audit yet*! TPM integration is partial.

**Key security note**: The proving key (~979KB) is NOT distributed. Only the verifying key (584 bytes) is embedded in the bootloader. You cannot forge proofs without the proving key, regardless of knowing the setup seed. The seed is deterministic for reproducibility but not because it's "development-only."

---

## Documentation Index

| Document | Audience | Contents |
|----------|----------|----------|
| [FAQ.md](FAQ.md) | Users | What it does, why it exists, basic concepts |
| [BUILD.md](BUILD.md) | Operators | Makefile targets, build process, deployment |
| [TECHNICAL.md](TECHNICAL.md) | Developers | Circuit internals, crypto details, implementation |
| [SECURITY.md](SECURITY.md) | Security researchers | Threat model, attack scenarios, limitations |
| [CEREMONY.md](CEREMONY.md) | Auditors | Trusted setup, key management, ceremony protocol |

---

## Quick Start

```bash
# Build and run
make all
make run

# Generate new ZK keys (trusted setup)
make generate-zk-keys
make show-vk

# Full pipeline with proof generation
make bootloader kernel sign-kernel generate-zk-proof embed-zk-proof esp run
```

---

## What This Is

A UEFI bootloader that requires three independent verifications before running a kernel:

1. **BLAKE3 integrity hash**: Binary hasn't been modified
2. **Ed25519 signature**: Authorized party approved the kernel
3. **Groth16 ZK proof**: Attestation constraints were satisfied

Miss any one, the machine resets. No exceptions.

---

## What This Is Not

- Not a malware detector (the ZK circuit doesn't analyze code at this stage but is something we'd love in future, it needs research)
- Not a replacement for Secure Boot (it complements it)
- Not protection against firmware-level attacks (we trust UEFI)
- Not a silver bullet (security requires proper key management)

---

## License

AGPL-3.0-or-later

Copyright 2026 NONOS Contributors
