// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
pub mod constants;
pub mod error;
pub mod mmu;
mod types;
#[cfg(test)]
mod tests;
pub use constants::*;
pub use error::{MmuError, MmuResult};
pub use mmu::{
    current_cr3, get_mmu, init_mmu, invalidate_page, map_kernel_memory,
    mmu_is_initialized as is_initialized, protection_flags, MMU,
};
pub use types::{PagePermissions, PageTableEntry, ProtectionFlags};
