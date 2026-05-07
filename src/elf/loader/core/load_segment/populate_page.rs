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

use core::ptr;

use crate::elf::errors::ElfError;
use crate::memory::addr::VirtAddr;
use crate::memory::frame_alloc;
use crate::memory::layout::DIRECTMAP_BASE;
use crate::memory::paging::manager::map_page_in_asid;
use crate::memory::paging::types::PagePermissions;

const PAGE: usize = 4096;

pub(super) fn populate_page(
    target_asid: u32,
    user_va: VirtAddr,
    perms: PagePermissions,
    file_bytes: &[u8],
    page_off: usize,
    file_size: usize,
    seg_size: usize,
) -> Result<(), ElfError> {
    let frame = frame_alloc::allocate_frame().ok_or(ElfError::MemoryAllocationFailed)?;
    map_page_in_asid(target_asid, user_va, frame, perms)
        .map_err(|_| ElfError::MemoryAllocationFailed)?;

    let dst = (DIRECTMAP_BASE + frame.as_u64()) as *mut u8;
    let in_file = file_size.saturating_sub(page_off).min(PAGE);
    let in_seg = seg_size.saturating_sub(page_off).min(PAGE);

    // SAFETY: eK@nonos.systems — frame phys came from frame_alloc, so
    // DIRECTMAP_BASE + phys is a fresh 4 KiB page we own.
    unsafe {
        ptr::write_bytes(dst, 0, PAGE);
        if in_file > 0 {
            ptr::copy_nonoverlapping(file_bytes[page_off..].as_ptr(), dst, in_file);
        }
    }
    let _ = in_seg;
    Ok(())
}
