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

use crate::loader::image::KernelImage;

use super::constants::PAGE_SIZE;
use super::mapper::map_4k_run;
use super::seg_flags::pte_flags_from_pf;
use super::table::PageTable;

// Install per-PT_LOAD phys -> virt mappings into the upper-half
// kernel window (PML4[511]) at 4 KiB granularity. Each segment's
// permission flags are translated through the strict W^X policy in
// `seg_flags::pte_flags_from_pf` before reaching the leaf entry.
//
// No-op for legacy low-half ET_EXEC images; the identity-low map
// already covers their text and they never set `virt_base`.
pub fn map_kernel_text(
    bs: &BootServices,
    pml4: PageTable,
    image: &KernelImage,
) -> Result<(), &'static str> {
    if image.virt_base == 0 {
        return Ok(());
    }

    for seg in image.segments() {
        if seg.size == 0 {
            continue;
        }
        if seg.virt & (PAGE_SIZE - 1) != 0 {
            return Err("map_kernel_text: segment virt not 4 KiB-aligned");
        }
        if seg.phys & (PAGE_SIZE - 1) != 0 {
            return Err("map_kernel_text: segment phys not 4 KiB-aligned");
        }
        let flags = pte_flags_from_pf(seg.flags)?;
        map_4k_run(bs, pml4, seg.virt, seg.phys, seg.size, flags)?;
    }
    Ok(())
}
