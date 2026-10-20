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

use super::types::{pte_flags, PageTableEntry};
use crate::memory::addr::PhysAddr;
use crate::memory::page_info::{self, PageFlags};

pub(super) fn share_frame(pa: PhysAddr) -> Result<(), &'static str> {
    if page_info::get_page_info(pa).is_none() {
        page_info::add_page(pa, None, PageFlags::USER).map_err(|e| e.as_str())?;
    }
    page_info::increment_ref_count(pa).map(|_| ()).map_err(|e| e.as_str())
}

pub(super) fn is_device_leaf(entry: PageTableEntry, huge: bool) -> bool {
    let pat = if huge { pte_flags::PAT_HUGE } else { pte_flags::PAT_4K };
    entry.raw() & (pte_flags::NO_CACHE | pte_flags::WRITE_THROUGH | pat) != 0
}

pub(super) fn release_frame(entry: PageTableEntry, frames: usize) {
    if is_device_leaf(entry, frames > 1) {
        return;
    }
    let pa = entry.phys_addr();
    if let Ok(0) = page_info::decrement_ref_count(pa) {
        let _ = page_info::remove_page(pa);
        free_frames(pa, frames);
    }
}

fn free_frames(pa: PhysAddr, frames: usize) {
    if frames == 1 {
        let _ = crate::memory::phys::free(crate::memory::phys::Frame(pa.as_u64()));
    } else {
        let _ = crate::memory::phys::free_contiguous(pa.as_u64(), frames);
    }
}
