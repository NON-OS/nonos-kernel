// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
extern crate alloc;
pub mod constants;
pub mod error;
pub mod manager;
mod stats;
pub mod types;
#[cfg(test)]
mod tests;
pub use constants::*;
pub use error::{RegionError, RegionResult};
pub use manager::*;
pub use types::{MemRegion, RegionFlags, RegionStats, RegionType};
