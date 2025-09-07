//! Time subsystem for NØNOS (x86_64).
//!
//! Provides timer primitives (e.g., PIT/LAPIC) and basic timekeeping utils.

pub mod timer;
pub mod rtc;

// If you want consumers to do `use crate::arch::time::*;`, you can re-export:
// pub use timer::*;
