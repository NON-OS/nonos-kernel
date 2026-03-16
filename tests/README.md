# NONOS Kernel Test Suite

## Running Tests

```bash
make test
```

## Test Structure

Tests are located inline with source code in `tests.rs` files throughout `src/`.

```
src/
├── arch/x86_64/
│   ├── acpi/tests.rs          # ACPI table parsing
│   ├── interrupt/tests.rs     # IDT, IRQ handling
│   └── time/*/tests.rs        # Timer subsystems
├── crypto/
│   ├── symmetric/*/tests.rs   # AES, ChaCha20
│   ├── asymmetric/*/tests.rs  # Ed25519, P-256
│   ├── hash/*/tests.rs        # SHA2, SHA3, BLAKE3
│   └── zk/*/tests.rs          # Groth16, Halo2
├── drivers/
│   ├── pci/tests/             # PCI enumeration
│   ├── xhci/tests/            # USB 3.0
│   ├── ahci/tests.rs          # SATA
│   └── nvme/tests.rs          # NVMe
├── memory/
│   ├── heap/tests.rs          # Heap allocator
│   ├── paging/tests.rs        # Page tables
│   └── frame/tests.rs         # Frame allocator
└── ...
```

## Test Categories

| Category | Count | Description |
|----------|-------|-------------|
| crypto | 353 | Cryptographic primitives |
| drivers | 643 | Hardware drivers |
| memory | 597 | Memory management |
| arch | 280 | Architecture-specific |
| modules | 112 | Kernel modules |
| fs | 54 | Filesystem |
| ipc | 51 | Inter-process communication |
| boot | 46 | Boot process |
| process | 42 | Process management |
| apps | 20 | Built-in apps |
| network | 13 | Network stack |
| ui | 4 | User interface |

## Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() {
        assert_eq!(2 + 2, 4);
    }
}
```

## Hardware-Dependent Tests

Tests requiring kernel hardware use conditional compilation:

```rust
#[test]
#[cfg(target_os = "nonos")]
fn test_hardware_timer() {
    // Only runs in kernel context
}
```

## Test Vectors

Cryptographic tests use NIST and RFC test vectors. See individual test files for references.
