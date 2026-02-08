# NØNOS Kernel Signing Tool (Ed25519)

Command-line tool for signing NØNOS kernel binaries with Ed25519. Supports both local key files for development and HashiCorp Vault transit backend for production environments where the private key never leaves secure hardware.

---

## Table of contents

- Overview
- Security model
- Build and install
- CLI usage (commands and examples)
- Key management
- Vault integration
- Signature format
- Embedding the public key
- Verification
- Operational policy
- Troubleshooting
- FAQ
- License

---

## Overview

This tool:
- Signs kernel binaries with Ed25519 (RFC 8032)
- Appends the 64-byte signature to the kernel binary
- Supports local 32-byte key files (dev) or Vault transit (prod)
- Outputs the public key in Rust array format for bootloader embedding
- Prints BLAKE3 hash of kernel and public key for verification

The bootloader verifies the signature before executing the kernel, establishing the first link in the boot trust chain.

---

## Security model

- Algorithm: Ed25519 (RFC 8032)
- Key storage:
  - Development: 32-byte seed file (keep secret, gitignore it)
  - Production: HashiCorp Vault transit engine (HSM-backed, key never exported)
- Signature binding: appended to kernel binary, verified in-place by bootloader
- Public key distribution: compiled into bootloader binary

Threat model:
- Compromised key = attacker can sign malicious kernels
- Always use Vault for release builds
- Rotate keys on suspected compromise

---

## Build and install

From repository root:
```
cargo build --release -p nonos-sign-kernel
```

Binary location:
```
target/release/sign-kernel
```

---

## CLI usage

### Local key signing (development)

```
sign-kernel \
  --key dev_signing_key.bin \
  --input target/x86_64-nonos/release/nonos-kernel \
  --output nonos-kernel.signed \
  --verify
```

### Vault signing (production)

```
export VAULT_TOKEN="s.xxxxx"

sign-kernel \
  --vault-addr https://vault.example.com:8200 \
  --vault-key-name nonos-kernel-signing \
  --input target/x86_64-nonos/release/nonos-kernel \
  --output nonos-kernel.signed \
  --verify
```

### Options

| Flag | Description |
|------|-------------|
| `-k, --key FILE` | Path to 32-byte Ed25519 seed file |
| `-i, --input FILE` | Kernel binary to sign |
| `-o, --output FILE` | Output path for signed kernel |
| `--vault-addr URL` | HashiCorp Vault address |
| `--vault-token TOKEN` | Vault token (or set VAULT_TOKEN env) |
| `--vault-key-name NAME` | Transit key name (default: nonos-kernel-signing) |
| `--verify` | Verify signature after signing |
| `-v, --verbose` | Print detailed output |

---

## Key management

### Generating a development key

```
dd if=/dev/urandom bs=32 count=1 > dev_signing_key.bin
chmod 600 dev_signing_key.bin
```

Never commit key files to git. Add to .gitignore:
```
*_signing_key*.bin
*.key
```

### Creating a Vault transit key

```
vault secrets enable transit

vault write transit/keys/nonos-kernel-signing \
  type=ed25519 \
  exportable=false \
  allow_plaintext_backup=false
```

---

## Vault integration

The tool uses Vault's transit secrets engine for secure signing:

1. Key stays in Vault (never exported)
2. Signing happens server-side via `transit/sign/:name`
3. Public key retrieved via `transit/keys/:name`

Required Vault policy:
```hcl
path "transit/sign/nonos-kernel-signing" {
  capabilities = ["update"]
}

path "transit/keys/nonos-kernel-signing" {
  capabilities = ["read"]
}
```

Vault namespaces are supported via the `--vault-namespace` flag.

---

## Signature format

The signed kernel binary structure:
```
+------------------+
| Original kernel  |  N bytes
+------------------+
| Ed25519 sig (R)  |  32 bytes
| Ed25519 sig (S)  |  32 bytes
+------------------+
```

Total size: kernel_size + 64 bytes

The bootloader reads the last 64 bytes as the signature and verifies against bytes [0..N-64].

---

## Embedding the public key

After signing, the tool prints the public key in Rust format:

```rust
pub const NONOS_SIGNING_KEY: &[u8; 32] = &[
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
];
```

Paste this into `nonos-boot/src/security/keys.rs` or your designated key registry.

---

## Verification

The `--verify` flag reads back the signed file and verifies the signature:

```
=== Verification ===
Signature verification: PASSED
```

For external verification:
```rust
use ed25519_dalek::{Verifier, VerifyingKey, Signature};

let signed_data = std::fs::read("nonos-kernel.signed")?;
let sig_offset = signed_data.len() - 64;
let payload = &signed_data[..sig_offset];
let sig_bytes = &signed_data[sig_offset..];

let pubkey = VerifyingKey::from_bytes(&NONOS_SIGNING_KEY)?;
let signature = Signature::from_bytes(sig_bytes.try_into()?);
pubkey.verify(payload, &signature)?;
```

---

## Operational policy

Development:
- Use local key files
- Keep keys out of version control
- Rotate frequently

Production:
- Always use Vault transit
- Enable audit logging on Vault
- Require MFA for Vault access
- Use CI/CD service accounts with limited scope

Release signing:
- Sign on isolated build machines
- Verify signature before distribution
- Publish public key hash with release notes

---

## Troubleshooting

**"Key file must be exactly 32 bytes"**
- Ed25519 seed must be 32 bytes. Generate with: `dd if=/dev/urandom bs=32 count=1 > key.bin`

**"vault connection failed"**
- Check VAULT_ADDR is reachable
- Verify network/firewall allows connection
- Check Vault is unsealed

**"permission denied" from Vault**
- Token lacks required capabilities
- Check policy includes transit/sign and transit/keys paths

**"key not found" from Vault**
- Transit key doesn't exist
- Check key name spelling
- Ensure transit engine is enabled

**"Signature verification: FAILED"**
- Key mismatch between signing and verification
- File corrupted during transfer
- Wrong public key embedded in bootloader

---

## FAQ

**Q: Why Ed25519 and not ECDSA or RSA?**
A: Ed25519 is fast, has small signatures (64 bytes), deterministic signing (no RNG needed at sign time) and strong security properties. Good fit for embedded bootloaders.

**Q: Can I use a hardware security module directly?**
A: Use Vault as the abstraction layer. Vault supports HSM backends (PKCS#11, AWS CloudHSM, etc.) and presents a uniform API.

**Q: Why print BLAKE3 hashes?**
A: BLAKE3 is used throughout NØNOS for fingerprinting. The printed hashes let you verify the kernel and public key match across builds and deployments.

**Q: Can I sign with multiple keys?**
A: Not currently. One signature per kernel. For key rotation, update the bootloader with the new public key before deploying kernels signed with the new key.

---

## License

AGPL-3.0 - See repository LICENSE file.
