// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pub mod constants;
pub mod entry;
pub mod error;
pub mod fs_gs;
pub mod ops;
pub mod percpu;
pub mod segments;
mod state;
pub mod stats;
pub mod syscall;
pub mod table;
pub mod tss;
#[cfg(test)]
mod tests;

pub use constants::*;
pub use entry::GdtEntry;
pub use error::GdtError;
pub use fs_gs::{get_fs_base, get_gs_base, get_kernel_gs_base, set_fs_base, set_gs_base, set_kernel_gs_base, swapgs};
pub use ops::{get_ist, get_kernel_stack, init, init_ap, is_initialized, set_ist, set_kernel_stack};
pub use percpu::PerCpuGdt;
pub use segments::reload_segments;
pub use stats::{get_stats, selectors, GdtStats, Selectors};
pub use syscall::setup_syscall;
pub use table::{Gdt, GdtPtr};
pub use tss::{Tss, TssEntry};
// Legacy aliases for compatibility
pub const NMI_IST_INDEX: u16 = IST_NMI as u16;
pub const DF_IST_INDEX: u16 = IST_DOUBLE_FAULT as u16;
pub const PF_IST_INDEX: u16 = IST_PAGE_FAULT as u16;
pub const MC_IST_INDEX: u16 = IST_MACHINE_CHECK as u16;
