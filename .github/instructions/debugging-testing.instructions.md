---
applyTo: "tests/**,src/test/**,src/kernel_selftest.rs"
---

# Debugging & Testing — NONOS Kernel

## Testing Modes

| Mode | Command | Environment | Use Case |
|------|---------|-------------|----------|
| **Host tests** | `cargo test --features std` | macOS/Linux host | Unit tests, crypto test vectors, parser tests |
| **QEMU boot** | `make run` | QEMU UEFI | Full system validation, driver tests |
| **Serial-only** | `make run-serial` | QEMU headless | CI, automated verification |
| **GDB debug** | `make debug` | QEMU + GDB `:1234` | Runtime debugging, memory inspection |
| **Self-tests** | Boot-time | Real hardware / QEMU | Hardware validation, crypto correctness |

## Writing Unit Tests

Colocated in source files or sibling `tests.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_mmio_region() {
        // Valid region
        assert!(validate_mmio_region(0x1000_0000, 4096).is_ok());

        // Zero address — must fail
        assert!(validate_mmio_region(0, 4096).is_err());

        // Overflow — must fail
        assert!(validate_mmio_region(u64::MAX - 10, 4096).is_err());
    }

    #[test]
    fn test_parse_html_strips_script() {
        let html = "<html><body><script>alert('xss')</script><p>Hello</p></body></html>";
        let doc = parse_html(html);
        let text = render_to_lines(html);
        assert!(!text.iter().any(|line| line.contains("alert")));
    }
}
```

### Test Naming Convention

`test_<thing_being_tested>` — descriptive enough that failing test name tells you what broke:

```rust
test_aes_gcm_encrypt_decrypt           // ✅ clear
test_capability_delegation_subset      // ✅ clear
test_it_works                          // ❌ useless name
test_1                                 // ❌ meaningless
```

### Test Structure

Follow Arrange-Act-Assert:

```rust
#[test]
fn test_capability_deny_expired() {
    // Arrange
    let token = CapabilityToken {
        expires_at_ms: Some(1000),
        // ...
    };
    set_mock_time(2000); // Past expiration

    // Act
    let result = check_capability(&token, Capability::IO);

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), CapError::Expired);
}
```

## The `std` Feature

Tests run on the host with `--features std`. This enables:

- `rand` crate for randomized testing
- Standard test harness (`#[test]`, `cargo test`)
- assertions, panics caught by test runner (not fatal)

**Guard test-only code:**

```rust
#[cfg(test)]
use std::vec::Vec;  // OK in tests

// NOT OK in kernel code — std doesn't exist
```

## Runtime Self-Tests

Location: `src/kernel_selftest.rs`

Called during boot to validate hardware in the real execution environment:

```rust
pub fn run() -> bool {
    let mut passed = true;

    passed &= test_serial_output();
    passed &= test_heap_allocation();
    passed &= test_page_mapping();
    passed &= test_aes_encrypt_decrypt();
    passed &= test_ed25519_verify();
    passed &= test_pci_enumeration();

    passed
}
```

Self-tests use `serial::println()` for output (no `println!` — there's no stdout).

## Debugging with QEMU + GDB

```bash
# Terminal 1: Start QEMU with GDB stub
make debug

# Terminal 2: Attach GDB
gdb target/x86_64-nonos/release/nonos-kernel
(gdb) target remote :1234
(gdb) break kernel_entry
(gdb) continue
```

### Useful GDB Commands

```
info registers          # All registers
x/10xg $rsp            # Stack dump (10 giant words)
x/20i $rip             # Disassemble at instruction pointer
print/x *(u64*)0xffff800000001000  # Read kernel memory
watch *0xffff800000002000          # Hardware watchpoint
info threads           # List all CPUs (SMP)
thread 2               # Switch to CPU 2
```

## Serial Debugging

The primary debug output channel. No `println!` — use serial:

```rust
use crate::sys::serial;

serial::println(b"[DEBUG] entering init_heap");
serial::print(b"[DEBUG] page_count = ");
serial::print_dec(page_count as u64);
serial::println(b"");

// For hex values:
serial::print(b"[DEBUG] cr3 = 0x");
serial::print_hex(cr3_value);
serial::println(b"");
```

### Serial-based investigation workflow

1. **Bracket the crash** — add serial prints before/after suspect code
2. **Binary search** — narrow down which line causes the fault
3. **Dump state** — print register/memory values at decision points
4. **Check assumptions** — print values you think you know but haven't verified

## Bug Investigation Protocol

1. **Reproduce** — write a `#[cfg(test)]` test or QEMU scenario
2. **Hypothesize** — state a concrete theory before touching code
3. **Instrument** — add serial breadcrumbs at decision points
4. **Verify** — confirm fix AND explain root cause
5. **Regress** — add `test_<bug_description>` that stays permanently

**Never make random changes hoping something sticks.** Every change must follow from a hypothesis.

## Test File Organization

```
tests/
├── arch/       # Architecture-specific tests
├── crypto/     # Crypto primitive test vectors
├── drivers/    # Driver unit tests
├── fs/         # Filesystem tests
├── ipc/        # IPC channel tests
├── memory/     # Memory management tests
├── network/    # Network stack tests
├── process/    # Process management tests
└── security/   # Security subsystem tests
```

## Common Test Patterns

### Crypto Test Vectors

```rust
#[test]
fn test_sha256_nist_vector() {
    // NIST FIPS 180-4, Section B.1
    let input = b"abc";
    let expected = hex!("ba7816bf...");
    assert_eq!(sha256(input), expected);
}
```

### Error Path Testing

```rust
#[test]
fn test_mmio_validate_rejects_null() {
    assert_eq!(
        validate_mmio_region(0, 4096),
        Err(MmioError::NullAddress)
    );
}

#[test]
fn test_mmio_validate_rejects_overflow() {
    assert_eq!(
        validate_mmio_region(u64::MAX - 10, 4096),
        Err(MmioError::AddressOverflow)
    );
}
```

### Hardware Mock Pattern

For tests that can't run on host (no real hardware):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Mock the hardware register read
    fn mock_read_register(_offset: u16) -> u32 { 0xDEAD_BEEF }

    #[test]
    fn test_device_probe_with_mock() {
        let result = probe_device(mock_read_register);
        assert!(result.is_ok());
    }
}
```

## CI Pipeline

`.github/workflows/ci.yml` runs:

1. `cargo fmt --check` — formatting
2. `cargo clippy` — lints (kernel + bootloader)
3. `cargo test --features std` — host tests
4. `make` — build kernel + bootloader + ESP image

All four must pass. Fix lint warnings before pushing.
