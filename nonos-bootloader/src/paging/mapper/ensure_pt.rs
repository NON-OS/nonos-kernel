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

// Return the PT phys backing `pd[pd_idx]`. Allocates a zeroed
// frame and links it in if empty. Refuses to subdivide an existing
// 2 MiB hugepage — the caller is asking for finer granularity than
// is already mapped.
pub fn ensure_pt(
    bs: &BootServices,
    pd: PageTable,
    pd_idx: usize,
    link_flags: u64,
) -> Result<u64, &'static str> {
    unsafe {
        let cur = pd.read_entry(pd_idx);
        if cur & PTE_P != 0 {
            if cur & PTE_PS != 0 {
                return Err("ensure_pt: refuse to subdivide existing 2 MiB hugepage");
            }
            return Ok(cur & ADDR_MASK_4K);
        }
        let new_pt = alloc_pt_frame(bs)?;
        pd.write_entry(pd_idx, new_pt | PTE_P | PTE_RW | link_flags);
        Ok(new_pt)
    }
}
