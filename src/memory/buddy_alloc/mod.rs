// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors

extern crate alloc;
pub mod allocator;
pub mod constants;
pub mod error;
mod stats;
mod types;
#[cfg(test)]
mod tests;
pub use allocator::*;
pub use constants::*;
pub use error::{BuddyAllocError, BuddyAllocResult};
pub use stats::{AllocationStatistics, ALLOCATION_STATS};
pub use types::{AllocStats, AllocatedBlock, BuddyBlock};
