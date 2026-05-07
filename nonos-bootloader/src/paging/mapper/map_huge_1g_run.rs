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

use crate::paging::constants::{HUGE_1G, PAGE_TABLE_ENTRIES, PTE_P, PTE_PS};
use crate::paging::table::PageTable;

use super::ensure_pdpt::ensure_pdpt;
use super::pdpt_index::pdpt_index;
use super::pml4_index::pml4_index;

// Map `count` consecutive 1-GiB-aligned virtual pages starting at
// `va_base` to the matching 1-GiB-aligned physical pages starting
// at `phys_base`, with the supplied flags (must include `PTE_P` and
// typically `PTE_PS`). Allocates one PDPT under each PML4 slot the
// run touches; subsequent runs into the same PML4 slot reuse that
// PDPT.
//
// Caller's `flags` must NOT include the address bits or PS bit;
// this function adds `PTE_P | PTE_PS` and the phys address.
pub fn map_huge_1g_run(
    bs: &BootServices,
    pml4: PageTable,
    va_base: u64,
    phys_base: u64,
    count: usize,
    flags: u64,
) -> Result<(), &'static str> {
    if va_base & (HUGE_1G - 1) != 0 {
        return Err("map_huge_1g_run: VA not 1 GiB-aligned");
    }
    if phys_base & (HUGE_1G - 1) != 0 {
        return Err("map_huge_1g_run: phys not 1 GiB-aligned");
    }

    for i in 0..count {
        let va = va_base + (i as u64) * HUGE_1G;
        let phys = phys_base + (i as u64) * HUGE_1G;
        let pml4_idx = pml4_index(va);
        let pdpt_idx = pdpt_index(va);

        if pdpt_idx >= PAGE_TABLE_ENTRIES {
            return Err("map_huge_1g_run: pdpt_idx overflow");
        }

        let pdpt_phys = ensure_pdpt(bs, pml4, pml4_idx, 0)?;
        let pdpt = PageTable::from_phys(pdpt_phys);
        unsafe {
            pdpt.write_entry(pdpt_idx, phys | PTE_P | PTE_PS | flags);
        }
    }
    Ok(())
}
