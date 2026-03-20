---
applyTo: "src/security/**"
---

# Security Hardening — NONOS Kernel

## Threat Model

The kernel is the TCB (Trusted Computing Base). An attacker may control:

- Syscall arguments (arbitrary user-space values)
- MMIO/DMA buffer contents (malicious hardware/firmware)
- Network packets (TLS downgrade, injection, replay)
- Capability tokens (forged or replayed)
- Physical memory (cold boot, DMA attacks)
- Timing side-channels (cache, branch prediction, power)

Every external input is hostile. Every boundary validates.

## Secure Boot Chain

```
UEFI Secure Boot → Bootloader (signed) → Kernel (Ed25519 signed)
                                        → Manifest verification
                                        → TPM PCR extension
                                        → ZK boot attestation proof
```

Location: `src/security/secure_boot/`

### TPM Integration

```rust
use crate::drivers::tpm;

// Extend PCR with kernel measurement
tpm::pcr_extend(PCR_KERNEL, &kernel_hash)?;

// Seal a secret to the current PCR state
let sealed = tpm::seal(secret_data, &pcr_policy)?;

// Unseal — only works if PCRs match the policy
let unsealed = tpm::unseal(&sealed)?;
```

## Spectre / Meltdown Mitigations

Location: `src/security/hardening/`

| Mitigation | MSR/Instruction | Feature Flag |
|------------|----------------|--------------|
| IBRS | IA32_SPEC_CTRL bit 0 | `nonos-ibrs` |
| STIBP | IA32_SPEC_CTRL bit 1 | `nonos-stibp` |
| SSBD | IA32_SPEC_CTRL bit 2 | `nonos-ssbd` |
| MDS (VERW) | VERW instruction | `nonos-mds` |
| L1TF | PTE inversion | default |
| Retpoline | Indirect branch thunks | compiler flag |

```rust
// Enable all mitigations during early boot:
pub fn init_spectre_mitigations() -> Result<(), SecurityError> {
    if cpu_has_feature(CpuFeature::IBRS) {
        write_msr(IA32_SPEC_CTRL, read_msr(IA32_SPEC_CTRL) | IBRS_BIT);
    }
    if cpu_has_feature(CpuFeature::SSBD) {
        write_msr(IA32_SPEC_CTRL, read_msr(IA32_SPEC_CTRL) | SSBD_BIT);
    }
    // MDS: issue VERW before returning to user space
    enable_mds_mitigation()?;
    Ok(())
}
```

## Stack Canaries & Guard Pages

```rust
// Stack canary — random value at bottom of stack frame
// Checked on function return; mismatch = stack corruption = panic
static STACK_CANARY: AtomicU64 = AtomicU64::new(0);

pub fn init_stack_canary(entropy: &[u8; 8]) {
    let canary = u64::from_le_bytes(*entropy);
    STACK_CANARY.store(canary, Ordering::SeqCst);
}

// Guard pages — unmapped page below each stack
// Any stack overflow triggers page fault instead of silent corruption
```

## Constant-Time Operations

All security-critical comparisons must be constant-time:

```rust
use subtle::ConstantTimeEq;

// ✅ CORRECT
fn verify_mac(computed: &[u8; 32], expected: &[u8; 32]) -> bool {
    computed.ct_eq(expected).into()
}

// ❌ WRONG — timing oracle
fn verify_mac(computed: &[u8; 32], expected: &[u8; 32]) -> bool {
    computed == expected  // Short-circuits on first mismatch
}
```

Applies to: MAC verification, signature checks, capability token comparison, password hashing, nonce validation.

## Audit Logging

Location: `src/security/audit/`

Every security-relevant event is logged:

```rust
audit_log(AuditEvent::CapabilityCheck {
    module: caller_module_id,
    capability: Capability::IO,
    granted: true,
    timestamp: current_time_ms(),
});

audit_log(AuditEvent::MmioAccess {
    address: phys_addr,
    size: 4096,
    granted: true,
});

audit_log(AuditEvent::SyscallDenied {
    syscall: SyscallNumber::Exec,
    reason: "insufficient capability",
    pid: current_pid(),
});
```

Audit log is append-only, stored in a ring buffer with overflow detection. Tampering with the audit log is a security violation.

## Key Management

Location: `src/security/keys/`

```
Sealed Key Database
├── Trusted Key Hashes (SHA-256 of authorized keys)
├── Key Rotation Records (timestamps, old→new mapping)
└── Revocation List (compromised key hashes)
```

- Keys are sealed via TPM — only unsealed when PCR state matches
- Rotation: new key is added, old key is deprecated with a grace period
- Revocation: immediate — revoked key hash is added to deny list

## Rootkit Scanning

Location: `src/security/rootkit/`

Runtime integrity checks:

- IDT pointer validation (hasn't been redirected)
- Syscall table integrity (no hooks)
- Kernel text hash verification (no code modification)
- Module signature verification (no unsigned modules loaded)

## Memory Safety Boundaries

### User ↔ Kernel Copy

Location: `src/usercopy/`

```rust
// ✅ CORRECT — validated copy from user space
let data = copy_from_user(user_ptr, size)?;  // Validates ptr is in user VA range

// ❌ WRONG — direct dereference of user pointer
let data = unsafe { *(user_ptr as *const T) };  // Kernel crash if ptr is invalid
```

### SMAP Enforcement

When SMAP is enabled, kernel cannot access user-space memory directly. All user-space access must go through explicit `stac`/`clac` bracketed regions (handled by `copy_from_user` / `copy_to_user`).

## Leak Detection

Location: `src/security/leak/`

- Monitor for kernel addresses leaking to user space via syscall returns
- Validate that KASLR base address never appears in user-visible data
- Check that freed memory is zeroed before returning to free pool

## Security Checklist for New Code

- [ ] All external inputs validated (syscall args, MMIO data, network packets)
- [ ] All secret comparisons constant-time (`subtle::ct_eq`)
- [ ] All secrets zeroed after use (`write_volatile` + compiler fence)
- [ ] All new capabilities declared in `abi/caps.toml`
- [ ] User pointers validated before dereference (`copy_from_user`)
- [ ] MMIO/DMA access goes through security validation layer
- [ ] Audit logging for all security-relevant operations
- [ ] No `unwrap()` on untrusted input paths
- [ ] No information leakage in error messages
