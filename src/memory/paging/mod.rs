// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

extern crate alloc;

pub mod constants;
pub mod error;
pub mod manager;
mod stats;
pub mod tlb;
pub mod types;

#[cfg(test)]
mod tests;

pub use constants::*;
pub use error::{PageFaultInfo, PagingError, PagingResult};
pub use manager::*;
pub use types::{PageMapping, PagePermissions, PageSize, PagingStats};
