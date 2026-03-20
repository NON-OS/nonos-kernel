---
applyTo: "src/drivers/**"
---

# Driver Development — NONOS Kernel

## Directory Layout

Every driver lives in `src/drivers/<name>/` with this structure:

```
src/drivers/<name>/
├── mod.rs      # Public API: submodule decls + pub use re-exports
├── types.rs    # Structs, enums, constants (#[repr(C)] for HW structs)
├── error.rs    # <Name>Error enum
└── *.rs        # Implementation files (private unless API)
```

Register in `src/drivers/mod.rs`: add `pub mod <name>`, re-exports, and call `init_<name>()` from `init_all_drivers()`.

## Error Enum Contract

Every driver error enum must implement:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciError {
    DeviceNotFound,
    MmioValidationFailed,
    DmaBufferInvalid,
    Timeout,
    // ...
}

impl AhciError {
    pub fn as_str(&self) -> &'static str { /* match each variant */ }
    pub fn code(&self) -> u32 { /* hex-categorized: 0x1xxx MMIO, 0x2xxx DMA, etc. */ }
    pub fn is_recoverable(&self) -> bool { /* true for timeouts, false for HW faults */ }
}

impl core::fmt::Display for AhciError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
```

## Security Validation Layer

**All hardware access must go through `drivers::security::*` before touching hardware.**

| Access Type | Validator | Location |
|-------------|-----------|----------|
| MMIO | `validate_mmio_region(base, size)` | `drivers/security/mmio.rs` |
| DMA | `validate_dma_buffer(addr, size, align)` | `drivers/security/dma.rs` |
| PCI Config | `validate_pci_access(bus, dev, func)` | `drivers/security/pci.rs` |
| LBA | `validate_lba_range(lba, count)` | `drivers/security/lba.rs` |
| Rate | `RateLimiter::check()` | `drivers/security/rate_limiter.rs` |

```rust
// ✅ CORRECT — validate before access
validate_mmio_region(bar_addr, 0x1000)?;
// SAFETY: address validated by validate_mmio_region above
let val = unsafe { core::ptr::read_volatile(bar_addr as *const u32) };

// ❌ WRONG — raw access without validation
let val = unsafe { core::ptr::read_volatile(bar_addr as *const u32) };
```

## DMA Buffer Rules

- Address must be above `KERNEL_PHYS_END`
- Alignment: minimum 4096 (page-aligned)
- Size: must not overflow when added to base address
- Call `validate_dma_buffer()` before every transfer
- Never reuse a DMA buffer across different device contexts without re-validation

## PCI Discovery Pattern

```rust
use crate::drivers::pci::{enumerate_devices, PciDevice};

pub fn init_mydriver() -> Result<(), MyDriverError> {
    let devices = enumerate_devices();
    for dev in &devices {
        if dev.vendor_id == MY_VENDOR && dev.device_id == MY_DEVICE {
            let bar0 = dev.bar(0).ok_or(MyDriverError::NoBar)?;
            validate_mmio_region(bar0, REGISTER_SPACE_SIZE)?;
            // Initialize device...
            return Ok(());
        }
    }
    Err(MyDriverError::DeviceNotFound)
}
```

## Rate Limiting

Every driver that touches hardware must implement rate limiting to prevent runaway I/O:

```rust
use crate::drivers::security::rate_limiter::RateLimiter;

static LIMITER: spin::Mutex<RateLimiter> = spin::Mutex::new(RateLimiter::new(1000)); // 1000 ops/sec

pub fn read_register(&self, offset: u16) -> Result<u32, MyDriverError> {
    LIMITER.lock().check().map_err(|_| MyDriverError::RateLimited)?;
    // ... actual read
}
```

## Critical Driver Registration

Security-relevant drivers must register with the critical driver tracker:

```rust
use crate::drivers::CriticalDriver;

// In init_<name>():
CriticalDriver::register(DriverType::Storage, SecurityLevel::High)?;
```

## Stats/Telemetry

Every driver should track operational statistics:

```rust
#[derive(Debug, Default)]
pub struct MyDriverStats {
    pub reads: u64,
    pub writes: u64,
    pub errors: u64,
    pub bytes_transferred: u64,
}
```

## Interrupt Handling in Drivers

- ISR body: acknowledge interrupt + set atomic flag. Nothing else.
- No allocation in ISRs. No lock acquisition. No I/O beyond the ack.
- Actual work happens in the deferred handler called from the main loop.

```rust
static PENDING: AtomicBool = AtomicBool::new(false);

fn my_device_isr() {
    acknowledge_interrupt_at_device();
    PENDING.store(true, Ordering::Release);
}

pub fn poll_device() {
    if PENDING.swap(false, Ordering::Acquire) {
        // Safe to allocate, lock, do I/O here
        handle_device_work();
    }
}
```

## Existing Drivers (Reference)

| Driver | Loc | PCI Class | Notes |
|--------|-----|-----------|-------|
| AHCI (SATA) | `drivers/ahci/` | Mass Storage | Port-multiplier, FIS, command list |
| NVMe | `drivers/nvme/` | NVM Express | Admin + I/O queue pairs |
| E1000 | `drivers/e1000/` | Network | Ring buffer TX/RX descriptors |
| RTL8139 | `drivers/rtl8139/` | Network | Legacy PCI NIC |
| RTL8168 | `drivers/rtl8168/` | Network | Gigabit variant |
| xHCI | `drivers/xhci/` | USB | USB 3.0 host controller |
| TPM 2.0 | `drivers/tpm/` | Security | PCR extend, sealing |
| GPU | `drivers/gpu/` | Display | Framebuffer, mode setting |
| HD Audio | `drivers/audio/` | Multimedia | CORB/RIRB command rings |
| I2C | `drivers/i2c/` | Serial | Touchpad, sensors |

## Anti-Patterns

- **No `unwrap()` or `expect()`** — hardware is unreliable, always return `Result`
- **No raw port I/O without validation** — use the security layer
- **No `static mut`** — use `spin::Mutex` or `AtomicBool`
- **No allocations in ISRs** — flag-and-defer only
- **No magic register offsets** — name every constant with its datasheet origin
