//! Architecture-specific subsystems for NØNOS (x86_64).
//!
//! Layout:
//! - `interrupt/` : APIC, IOAPIC, legacy PIC setup and interrupt plumbing
//! - `keyboard/`  : PS/2 keyboard (scancode handling, simple input)
//! - `time/`      : PIT/LAPIC timer utilities and timekeeping

pub mod interrupt;
pub mod keyboard;
pub mod time;
pub mod x86_64;
