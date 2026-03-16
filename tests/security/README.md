# Security Module Tests

## Location

`src/security/*/tests.rs`

## Coverage

### Memory Sanitization

- Zeroization on free
- Stack canaries
- DoD 5220.22-M wipe

Source: `src/security/hardening/memory_sanitization/tests.rs`

### ASLR

- Randomization quality
- Entropy sources
- Layout verification

Source: `src/security/hardening/aslr/tests.rs`

### Secure Boot

- Signature verification
- Chain of trust
- Attestation

Source: `src/security/boot/tests.rs`

## Running

```bash
cargo test --lib --features std security::
```
