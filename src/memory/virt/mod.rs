// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors

extern crate alloc;
pub mod constants;
pub mod error;
pub mod manager;
mod stats;
mod types;
#[cfg(test)]
mod tests;
pub use constants::*;
pub use error::{VmError, VmResult};
pub use manager::*;
pub use stats::{VmStats, VM_STATS};
pub use types::{MappedRange, PageSize, VmFlags, VmStatsSnapshot};
