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

use uefi::table::boot::BootServices;

use crate::paging::constants::{ADDR_MASK_4K, PTE_P, PTE_PS, PTE_RW};
use crate::paging::frame::alloc_pt_frame;
use crate::paging::table::PageTable;

// Return the PD phys backing `pdpt[pdpt_idx]`. Allocates a zeroed
// frame and links it in if the slot is empty. Refuses to descend
// through an existing 1 GiB hugepage entry — the caller is asking
// for finer granularity than what is already mapped.
pub fn ensure_pd(
    bs: &BootServices,
    pdpt: PageTable,
    pdpt_idx: usize,
    link_flags: u64,
) -> Result<u64, &'static str> {
    unsafe {
        let cur = pdpt.read_entry(pdpt_idx);
        if cur & PTE_P != 0 {
            if cur & PTE_PS != 0 {
                return Err("ensure_pd: refuse to subdivide existing 1 GiB hugepage");
            }
            return Ok(cur & ADDR_MASK_4K);
        }
        let new_pd = alloc_pt_frame(bs)?;
        pdpt.write_entry(pdpt_idx, new_pd | PTE_P | PTE_RW | link_flags);
        Ok(new_pd)
    }
}
