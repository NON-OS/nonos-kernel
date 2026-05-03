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

use super::super::error::{MmuError, MmuResult};
use super::super::types::{PagePermissions, ProtectionFlags};
use super::core::MMU;
use crate::memory::addr::{PhysAddr, VirtAddr};
use spin::Once;

static MMU_INSTANCE: Once<MMU> = Once::new();

pub fn init_mmu() -> MmuResult<()> {
    MMU_INSTANCE.call_once(MMU::new).initialize()
}
pub fn get_mmu() -> MmuResult<&'static MMU> {
    MMU_INSTANCE.get().ok_or(MmuError::NotInitialized)
}

pub fn map_kernel_memory(
    virt_start: VirtAddr,
    phys_start: PhysAddr,
    size: usize,
    writable: bool,
    executable: bool,
) -> MmuResult<()> {
    let permissions =
        PagePermissions { writable, user_accessible: false, executable, cache_disabled: false };
    get_mmu()?.map_kernel_range(virt_start, phys_start, size, permissions)
}

pub fn invalidate_page(addr: VirtAddr) -> MmuResult<()> {
    get_mmu()?.invalidate_tlb_page(addr);
    Ok(())
}
pub fn current_cr3() -> MmuResult<u64> {
    Ok(get_mmu()?.get_current_cr3())
}
pub fn mmu_is_initialized() -> bool {
    MMU_INSTANCE.get().map(|m| m.is_initialized()).unwrap_or(false)
}
pub fn protection_flags() -> MmuResult<ProtectionFlags> {
    Ok(get_mmu()?.get_protection_flags())
}
