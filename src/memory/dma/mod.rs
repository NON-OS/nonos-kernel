// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors

extern crate alloc;
pub mod allocator;
pub mod constants;
pub mod error;
pub mod pool;
mod stats;
pub mod types;
#[cfg(test)]
mod tests;
pub use constants::*;
pub use error::{DmaError, DmaResult};
pub use allocator::*;
pub use pool::DmaPool;
pub use types::{DmaConstraints, DmaDirection, DmaRegion, DmaStatsSnapshot, StreamingMapping};
