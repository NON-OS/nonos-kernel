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

use crate::paging::constants::{ADDR_MASK_4K, PTE_P, PTE_RW};
use crate::paging::frame::alloc_pt_frame;
use crate::paging::table::PageTable;

// Return the PDPT phys backing `pml4[pml4_idx]`. Allocates a fresh
// zeroed frame and links it into the PML4 if the slot is empty.
// Caller's `link_flags` is stitched onto the new pointer entry
// (typically `PTE_RW`); `PTE_P` is added unconditionally.
pub fn ensure_pdpt(
    bs: &BootServices,
    pml4: PageTable,
    pml4_idx: usize,
    link_flags: u64,
) -> Result<u64, &'static str> {
    unsafe {
        let cur = pml4.read_entry(pml4_idx);
        if cur & PTE_P != 0 {
            return Ok(cur & ADDR_MASK_4K);
        }
        let new_pdpt = alloc_pt_frame(bs)?;
        pml4.write_entry(pml4_idx, new_pdpt | PTE_P | PTE_RW | link_flags);
        Ok(new_pdpt)
    }
}
