// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use super::super::super::constants::PAGE_SIZE;
use super::super::super::error::{MmuError, MmuResult};
use super::super::super::types::PagePermissions;
use super::super::core::MMU;
use x86_64::{PhysAddr, VirtAddr};

impl MMU {
    pub fn map_kernel_range(
        &self,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: usize,
        permissions: PagePermissions,
    ) -> MmuResult<()> {
        if !self.is_initialized() {
            return Err(MmuError::NotInitialized);
        }
        let cr3 = self.get_current_cr3();
        if cr3 == 0 {
            return Err(MmuError::NoPageTableLoaded);
        }
        let pml4_virt = self.frame_to_virt(PhysAddr::new(cr3));
        self.map_memory_range(pml4_virt, virt_start, phys_start, size, permissions)
    }

    pub(super) fn map_memory_range(
        &self,
        pml4_virt: VirtAddr,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: usize,
        permissions: PagePermissions,
    ) -> MmuResult<()> {
        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        for i in 0..pages {
            let va = VirtAddr::new(virt_start.as_u64() + (i * PAGE_SIZE) as u64);
            let pa = PhysAddr::new(phys_start.as_u64() + (i * PAGE_SIZE) as u64);
            self.map_single_page(pml4_virt, va, pa, permissions)?;
        }
        Ok(())
    }
}
