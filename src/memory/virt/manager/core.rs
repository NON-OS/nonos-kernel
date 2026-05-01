// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::super::error::VmResult;
use super::super::types::MappedRange;
use crate::memory::layout;
use alloc::vec::Vec;
use crate::memory::addr::{PhysAddr, VirtAddr};

pub struct VirtualMemoryManager {
    pub(super) cr3_frame: PhysAddr,
    pub(super) kernel_page_table: Option<VirtAddr>,
    pub(super) mapped_ranges: Vec<MappedRange>,
    pub(super) next_free_addr: u64,
    pub(super) initialized: bool,
}

impl VirtualMemoryManager {
    pub const fn new() -> Self {
        Self {
            cr3_frame: PhysAddr::new(0),
            kernel_page_table: None,
            mapped_ranges: Vec::new(),
            next_free_addr: layout::VMAP_BASE,
            initialized: false,
        }
    }

    pub fn init(&mut self, cr3_frame: PhysAddr) -> VmResult<()> {
        if self.initialized {
            return Ok(());
        }
        self.cr3_frame = cr3_frame;
        self.kernel_page_table = Some(VirtAddr::new(layout::KERNEL_BASE + cr3_frame.as_u64()));
        self.mapped_ranges.clear();
        self.next_free_addr = layout::VMAP_BASE;
        self.initialized = true;
        Ok(())
    }

    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for VirtualMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}
