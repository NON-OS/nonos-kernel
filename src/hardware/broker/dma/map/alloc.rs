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

use crate::hardware::broker::dma::types::DmaMapError;
use crate::memory::layout::DIRECTMAP_BASE;
use crate::memory::phys::{alloc_contiguous, free_contiguous, AllocFlags};

// Allocate `pages` physically-contiguous frames and re-scrub through
// the direct map so the buffer is provably zero before it leaves the
// kernel. The phys allocator's ZERO flag is best-effort across zones;
// the volatile loop here is the load-bearing scrub.
pub(super) fn alloc_and_zero(pages: u64, length: u64) -> Result<u64, DmaMapError> {
    let phys_start = alloc_contiguous(pages as usize, AllocFlags::DMA | AllocFlags::ZERO)
        .ok_or(DmaMapError::NoMemory)?;
    zero_run(phys_start, length);
    Ok(phys_start)
}

pub(super) fn free(phys_start: u64, pages: u64) {
    let _ = free_contiguous(phys_start, pages as usize);
}

// SAFETY: ek@nonos.systems — DIRECTMAP_BASE + phys is the canonical
// kernel mapping for the frames; the run is owned exclusively by the
// broker between `alloc_contiguous` and `records::insert`, so no
// other path aliases the VA. Volatile prevents elision.
fn zero_run(physical_start: u64, length: u64) {
    let kva = (DIRECTMAP_BASE + physical_start) as *mut u64;
    let words = (length / 8) as usize;
    unsafe {
        for i in 0..words {
            core::ptr::write_volatile(kva.add(i), 0);
        }
    }
}
