// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
extern crate alloc;
pub mod constants;
pub mod error;
pub mod manager;
mod ops;
mod stats;
mod types;
#[cfg(test)]
mod tests;
pub use constants::*;
pub use error::{MmioError, MmioResult};
pub use manager::*;
pub use ops::{mmio_r16, mmio_r32, mmio_r64, mmio_r8, mmio_w16, mmio_w32, mmio_w64, mmio_w8};
pub use stats::{MmioStats, MMIO_STATS};
pub use types::{MmioFlags, MmioRegion, MmioStatsSnapshot};
