# Security Model

Clear threat model: what we verify, what's out of scope and why.

---

## Core Security Properties

### 1. Kernel Authorization

Only kernels signed by a trusted Ed25519 key can boot. An attacker who modifies the kernel binary cannot boot it and signature verification fails, machine resets.

### 2. Attestation Binding

Every kernel requires a valid Groth16 proof alongside the signature. Stealing the signing key alone is insufficient, an attacker also needs the proving key (~979KB, not distributed) to generate proofs.

### 3. Defense in Depth

Compromise requires breaching MULTIPLE independent systems:
- Signing key (Ed25519)
- Proving key (Groth16)
- Circuit constraints (must produce valid witness)

Compare to signature-only boot: steal one key, game over. Here: steal one key, still blocked.

### 4. Rollback Resistance

Mechanisms to prevent booting old vulnerable kernels:
- Key versioning with minimum version enforcement
- Program hash rotation (new circuit = new hash = old proofs invalid)
- Explicit key revocation

---

## Architectural Boundaries

These are not weaknesses, they're fundamental scope limits that apply to ALL boot-time security systems.

### Runtime Kernel behavior

Once the kernel runs, the bootloader's job is done. Buffer overflows, privilege escalation, kernel exploits—these are kernel security concerns, not boot security.

**Every bootloader has this boundary.** Secure Boot, TPM measured boot, Android verified boot—none of them protect against runtime exploits. That's what kernel hardening, ASLR and exploit mitigations are for.

### Firmware Integrity

The bootloader runs ON the firmware. If UEFI is compromised (rootkits, SMM exploits, Intel ME/AMD PSP), the attacker controls everything below us.

**Mitigation**: TPM measured boot can detect firmware tampering. Intel Boot Guard can lock firmware. These are complementary technologies, not replacements.

### Build Pipeline Trust

The ZK circuit doesn't analyze kernel code, it's an attestation binding mechanism. If a compromised compiler inserts a backdoor and the result gets signed + proven, it boots.

**This is a key management problem, not a bootloader problem.** Whoever controls the signing and proving keys controls what boots. Protect those keys like you'd protect root credentials.

### Physical Access

If an attacker has physical access and Secure Boot is off, they can replace the bootloader binary itself. With hardware implants or JTAG, software security is irrelevant.

**Mitigation**: Enable Secure Boot. Sign the bootloader. Use full-disk encryption. Physical security is a separate domain.

---

## The Actual Threat Model

**We protect against**: Remote attackers who gain write access to the EFI System Partition. They can modify or replace the kernel binary, but it won't boot without valid signature AND proof.

**We don't protect against**: Attackers who compromise your build infrastructure, steal both keys and produce properly attested malicious kernels. That's an operational security failure, not a cryptographic one.

**We complement**: Secure Boot (verifies bootloader), TPM (measures boot chain), full-disk encryption (protects data at rest). Use all of them together.

---

## Key Security Architecture

### Proving Key Protection

The proving key allows generating valid proofs. It's ~979KB and NOT distributed—only the 584-byte verifying key is embedded in bootloaders.

Operational requirements:
- Store in secure location (HSM, vault, air-gapped build server)
- Limit access to automated build systems
- Audit all access
- Rotate if compromise suspected

### Signing Key Protection

Same requirements as proving key. Ideally store separately—different systems, different access controls so compromising one doesn't give you both.

### Setup Seed

Current seed `nonos-production-attestation-v1-2026` is deterministic for reproducibility. Anyone who knows the seed can regenerate the same keys but they'd also need to replace the VK in your bootloader binary, which requires rebuilding and redistributing the bootloader.

For maximum paranoia: use a random seed, protect the proving key, destroy the seed.

---

## TPM Integration Status

| Feature | Status |
|---------|--------|
| TPM detection | Working |
| PCR extension | Working |
| RNG from TPM | Working |
| Remote attestation (quotes) | Planned |
| Sealed secrets | Planned |
| NVRAM rollback counters | Planned |

The PCR preimage in the circuit is currently a placeholder. Full TPM integration would read actual Platform Configuration Register values from hardware.

---

## Comparison Matrix

| Feature | Secure Boot | TPM Measured | ZeroState |
|---------|-------------|--------------|-----------|
| **What it checks** | Bootloader signature | Everything (passive) | Kernel signature + ZK proof |
| **Authorization** | Yes | No (measure only) | Yes |
| **Attestation** | No | Yes (reveals all) | Yes (ZK privacy) |
| **Key theft recovery** | Revoke key | N/A | Need BOTH keys |
| **Policy flexibility** | Binary | External verifier | Circuit-defined |

---

## Security Properties Summary

**Real protections:**
- Unauthorized kernels cannot boot
- Single key compromise insufficient
- Rollback to vulnerable versions blockable
- Attestation without revealing hardware details

**Architectural limits (shared with all boot security):**
- Doesn't protect running kernel
- Doesn't protect against firmware attacks
- Doesn't analyze kernel code for backdoors
- Trusts whoever controls the keys

**Bottom line:** This is our cryptographic security with real defense-in-depth properties. Definitely, it's not magic, but it's significantly harder to defeat than signature-only boot.
