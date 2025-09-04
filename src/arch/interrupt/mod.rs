//! Interrupt subsystem for NØNOS (x86_64).
//!
//! Modules:
//! - `apic`      : Local APIC / xAPIC/LAPIC setup
//! - `ioapic`    : I/O APIC routing
//! - `pic_legacy`: 8259 PIC (legacy) fallback / masking

pub mod apic;
pub mod ioapic;
pub mod pic_legacy;

// If you want consumers to do `use crate::arch::interrupt::*;` uncomment:
// pub use apic::*;
// pub use ioapic::*;
// pub use pic_legacy::*;
