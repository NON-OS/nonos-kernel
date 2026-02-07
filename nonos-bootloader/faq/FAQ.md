# Frequently Asked Questions

Honest answers about what this bootloader does and why.

---

## The Basics

### What is the nonos-bootloader?

We are building a UEFI bootloader that refuses to run your kernel unless it passes three checks: a BLAKE3 integrity hash, an Ed25519 signature and a Groth16 zero-knowledge proof. Miss any one of these, the machine resets. No exceptions, no recovery mode, no backdoor.

The signature proves someone with authority approved the kernel. The ZK proof proves that certain attestation conditions were met when the proof was generated. Together, they make it harder for an attacker to boot malicious code even if they compromise part of the system.

---

### What does the ZK circuit verify?

The current circuit is simpler than you might expect. It verifies:

1. The program hash matches a hardcoded expected value (confirms the proof came from the right circuit)
2. The PCR preimage (64 bytes) contains at least one non-zero byte (placeholder check)
3. A hardware attestation value meets a minimum threshold (0x1000)
4. The capsule commitment is non-zero

The circuit does NOT analyze kernel code, verify the compiler, check for forbidden instructions, or prove anything about source code. It's an attestation binding mechanism, not a program analyzer.

---

### Who is this for?

**Good fit:**
- High-security environments (military, finance, infrastructure)
- Privacy-focused users wanting attestation without revealing hardware details
- Researchers exploring ZK in systems software

**Bad fit:**
- Casual users who just want to boot
- Extreme resource-constrained embedded systems
- Anyone who needs <1 second boots (ZK adds ~30ms)

---

### Does this replace Secure Boot?

No. It complements Secure Boot.

**Secure Boot**: Verifies the bootloader binary is signed. Prevents loading unsigned bootloaders.

**Zero-State**: Verifies the kernel is signed AND attested. Runs after Secure Boot loaded the bootloader.

For maximum security: Secure Boot verifies bootloader, bootloader verifies kernel. Two layers.

---

### What problem does this solve that Secure Boot doesn't?

Secure Boot: "This binary was signed by a trusted party."

Zero-State: "This binary was signed AND carries a valid attestation proof."

Concrete scenario: Signing key stolen.
- With just Secure Boot: Attacker signs malware, game over.
- With ZeroState: Attacker also needs proving key, and valid witnesses. Multiple independent things to compromise.

---

### Can I run custom kernels?

Not with the stock bootloader. It only accepts kernels signed with the embedded trusted key.

To run your own:
1. Generate your own Ed25519 keypair
2. Run trusted setup for your own proving/verifying keys
3. Build a bootloader with YOUR verifying key embedded
4. Sign and attest your custom kernels

This is the whole point. Only authorized kernels boot.

---

### What's the size overhead?

**On kernel binary:**
- 64 bytes for signature
- ~272+ bytes for proof block
- Total: ~350-500 bytes

**On bootloader binary:**
- Arkworks verification code adds ~200-300 KB

Negligible for a multi-megabyte kernel.

---

### What hardware has this been tested on?

Mostly QEMU with OVMF. Known to work:
- QEMU with OVMF firmware
- VirtualBox with EFI enabled
- x86_64 UEFI systems with GOP graphics
- HP x3 laptops - On bootloader side works smoothly excellent. USB Image boot.

UEFI implementations vary. If you hit firmware bugs, file an issue.

---

### Is this the first ZK-verified bootloader?

As far as we know, yes.

Prior art (Intel TXT, AMD SEV, TPM measured boot, IMA, dm-verity, Android/ChromeOS verified boot) uses hardware attestation or signatures, not ZK proofs. Combining Ed25519 signatures with Groth16 proofs in a UEFI bootloader appears to be novel.

---

## Honest Summary

This bootloader does real cryptography. The Ed25519 signatures are real. The BLAKE3 hashing is real. The Groth16 proofs are real.

What it doesn't do is magic. The ZK circuit is simple. The security model assumes you trust whoever has the signing and proving keys. If your build pipeline is compromised, you lose.

The value is defense in depth. An attacker needs to compromise multiple independent things. That's harder than compromising just one thing.

---

See also:
- [BUILD.md](BUILD.md) - Build instructions
- [TECHNICAL.md](TECHNICAL.md) - Crypto implementation details
- [SECURITY.md](SECURITY.md) - Threat model
- [CEREMONY.md](CEREMONY.md) - Trusted setup documentation
