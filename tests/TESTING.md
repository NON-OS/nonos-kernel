# NONOS Kernel Testing

## Quick Start

```bash
# Host tests (std mode)
make test

# Kernel tests (boot-time)
make run   # watch console output for SELFTEST results
```

## Test Results

- **Total:** 2,004 tests
- **Passing:** 1,570 (98.7%)
- **Failing:** 20 (time overflow in userspace)

## Structure

Tests live with source code:

```
src/
├── crypto/symmetric/aes/tests.rs
├── crypto/asymmetric/ed25519/tests.rs
├── drivers/pci/tests/
├── memory/heap/tests.rs
└── ...
```

Documentation in `tests/`:

```
tests/
├── README.md
├── crypto/README.md
├── arch/README.md
├── drivers/README.md
├── memory/README.md
├── fs/README.md
├── ipc/README.md
├── process/README.md
├── network/README.md
└── security/README.md
```

## Module Coverage

| Module | Tests | Status |
|--------|-------|--------|
| drivers | 643 | pass |
| memory | 597 | pass |
| crypto | 353 | pass |
| arch | 280 | pass |
| modules | 112 | pass |
| fs | 54 | pass |
| ipc | 51 | 31 pass, 20 time-dependent |
| boot | 46 | pass |
| process | 42 | time-dependent |
| apps | 20 | pass |
| network | 13 | pass |
| ui | 4 | pass |

## Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example() {
        let result = do_something();
        assert_eq!(result, expected);
    }
}
```

## Hardware Tests

For tests requiring kernel hardware:

```rust
#[test]
#[cfg(target_os = "nonos")]
fn test_hardware() {
    // runs only in kernel
}
```

## CI

Tests run automatically on push via `make test`.
