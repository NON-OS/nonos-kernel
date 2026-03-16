# Architecture Module Tests

## Location

`src/arch/x86_64/*/tests.rs`

## Coverage

### ACPI (68 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| Table parsing | 24 | `src/arch/x86_64/acpi/tests/` |
| Power management | 18 | `src/arch/x86_64/acpi/power/tests.rs` |
| MADT/APIC | 14 | `src/arch/x86_64/acpi/data/tests.rs` |
| NUMA | 12 | `src/arch/x86_64/acpi/tests/data_tests.rs` |

### Interrupts (45 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| IDT setup | 15 | `src/arch/x86_64/interrupt/idt/tests.rs` |
| IRQ handling | 18 | `src/arch/x86_64/interrupt/irq/tests.rs` |
| APIC | 12 | `src/arch/x86_64/interrupt/apic/tests.rs` |

### Time (52 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| TSC | 14 | `src/arch/x86_64/time/tsc/tests.rs` |
| HPET | 12 | `src/arch/x86_64/time/hpet/tests.rs` |
| PIT | 8 | `src/arch/x86_64/time/pit/tests.rs` |
| RTC | 10 | `src/arch/x86_64/time/rtc/tests.rs` |
| Timer API | 8 | `src/arch/x86_64/time/timer/tests.rs` |

### CPU (38 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| Feature detection | 12 | `src/arch/x86_64/cpu/features/tests.rs` |
| MSRs | 14 | `src/arch/x86_64/cpu/msr/tests.rs` |
| CPUID | 12 | `src/arch/x86_64/cpu/cpuid/tests.rs` |

### GDT/Segmentation (24 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| GDT setup | 12 | `src/arch/x86_64/gdt/tests.rs` |
| TSS | 8 | `src/arch/x86_64/gdt/tss/tests.rs` |
| Segments | 4 | `src/arch/x86_64/gdt/segment/tests.rs` |

### Syscall (31 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| Handler | 15 | `src/arch/x86_64/syscall/tests.rs` |
| ABI | 16 | `src/arch/x86_64/syscall/abi/tests.rs` |

## Running

```bash
cargo test --lib --features std arch::
```

## Notes

Some tests require kernel context (real hardware timers). These are gated:

```rust
#[test]
#[cfg(target_os = "nonos")]
fn test_rdtsc() { ... }
```
