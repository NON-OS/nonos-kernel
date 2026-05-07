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

use crate::paging::constants::{PAGE_SIZE, PTE_P, PTE_PS};
use crate::paging::table::PageTable;

use super::ensure_pd::ensure_pd;
use super::ensure_pdpt::ensure_pdpt;
use super::ensure_pt::ensure_pt;
use super::pd_index::pd_index;
use super::pdpt_index::pdpt_index;
use super::pml4_index::pml4_index;
use super::pt_index::pt_index;

// Map a contiguous run of 4 KiB pages from `phys_base` to `va_base`
// for `size` bytes. Walks PML4 -> PDPT -> PD -> PT, allocating
// intermediate frames as needed, and writes leaf entries with the
// supplied flags. Caller's flags must NOT include the address bits
// or the PS bit; this function adds `PTE_P` and the phys address.
//
// Both `va_base` and `phys_base` must be 4 KiB-aligned. `size` is
// rounded up to the next page boundary.
pub fn map_4k_run(
    bs: &BootServices,
    pml4: PageTable,
    va_base: u64,
    phys_base: u64,
    size: u64,
    flags: u64,
) -> Result<(), &'static str> {
    if va_base & (PAGE_SIZE - 1) != 0 {
        return Err("map_4k_run: VA not 4 KiB-aligned");
    }
    if phys_base & (PAGE_SIZE - 1) != 0 {
        return Err("map_4k_run: phys not 4 KiB-aligned");
    }
    if flags & PTE_PS != 0 {
        return Err("map_4k_run: PTE_PS set on a 4 KiB mapping");
    }

    let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;

    for i in 0..pages {
        let va = va_base + i * PAGE_SIZE;
        let phys = phys_base + i * PAGE_SIZE;

        let pml4_idx = pml4_index(va);
        let pdpt_idx = pdpt_index(va);
        let pd_idx = pd_index(va);
        let pt_idx = pt_index(va);

        let pdpt_phys = ensure_pdpt(bs, pml4, pml4_idx, 0)?;
        let pdpt = PageTable::from_phys(pdpt_phys);

        let pd_phys = ensure_pd(bs, pdpt, pdpt_idx, 0)?;
        let pd = PageTable::from_phys(pd_phys);

        let pt_phys = ensure_pt(bs, pd, pd_idx, 0)?;
        let pt = PageTable::from_phys(pt_phys);

        unsafe {
            pt.write_entry(pt_idx, phys | PTE_P | flags);
        }
    }

    Ok(())
}
