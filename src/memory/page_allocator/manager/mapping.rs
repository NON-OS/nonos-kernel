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

use super::super::error::{PageAllocError, PageAllocResult};
use crate::memory::{frame_alloc, layout, virt};
use alloc::vec::Vec;
use crate::memory::addr::{PhysAddr, VirtAddr};

pub(super) fn allocate_virtual_pages(page_count: usize) -> PageAllocResult<VirtAddr> {
    let mut allocated_frames = Vec::new();
    for _ in 0..page_count {
        let frame = frame_alloc::allocate_frame().ok_or(PageAllocError::FrameAllocationFailed)?;
        allocated_frames.push(frame);
    }
    let first_frame = allocated_frames[0];
    let va = VirtAddr::new(layout::VMAP_BASE + first_frame.as_u64());
    for (i, frame) in allocated_frames.iter().enumerate() {
        let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
        map_page(page_va, *frame)?;
    }
    Ok(va)
}

pub(super) fn free_virtual_pages(va: VirtAddr, page_count: usize) -> PageAllocResult<()> {
    for i in 0..page_count {
        let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
        let pa = get_physical_address(page_va)?;
        unmap_page(page_va)?;
        let _ = frame_alloc::deallocate_frame(pa);
    }
    Ok(())
}

fn map_page(va: VirtAddr, pa: PhysAddr) -> PageAllocResult<()> {
    virt::map_page_4k(va, pa, true, false, false).map_err(|_| PageAllocError::MappingFailed)
}

fn unmap_page(va: VirtAddr) -> PageAllocResult<()> {
    virt::unmap_page(va).map_err(|_| PageAllocError::UnmapFailed)
}

pub(super) fn get_physical_address(va: VirtAddr) -> PageAllocResult<PhysAddr> {
    virt::translate_addr(va).map_err(|_| PageAllocError::TranslationFailed)
}
