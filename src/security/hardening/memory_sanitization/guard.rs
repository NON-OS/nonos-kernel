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

use super::erase::sanitize;

pub struct GuardPage {
    pub address: u64,
    pub size: usize,
}

pub fn allocate_with_guards(size: usize) -> Option<(*mut u8, GuardPage, GuardPage)> {
    const PAGE_SIZE: usize = 4096;
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let total_size = aligned_size + PAGE_SIZE * 2;

    let base = crate::memory::phys::alloc_contiguous(total_size / PAGE_SIZE, crate::memory::phys::AllocFlags::ZERO)?;
    let base_ptr = base as *mut u8;

    let guard_low = GuardPage {
        address: base,
        size: PAGE_SIZE,
    };

    let guard_high = GuardPage {
        address: base + aligned_size as u64 + PAGE_SIZE as u64,
        size: PAGE_SIZE,
    };

    let _ = crate::memory::virt::unmap_page(x86_64::VirtAddr::new(guard_low.address));
    let _ = crate::memory::virt::unmap_page(x86_64::VirtAddr::new(guard_high.address));

    // SAFETY: base_ptr is valid, adding PAGE_SIZE keeps us within allocation
    let data_ptr = unsafe { base_ptr.add(PAGE_SIZE) };

    Some((data_ptr, guard_low, guard_high))
}

pub fn free_with_guards(ptr: *mut u8, size: usize, guard_low: GuardPage, _guard_high: GuardPage) {
    sanitize(ptr, size);

    const PAGE_SIZE: usize = 4096;
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let total_pages = (aligned_size + PAGE_SIZE * 2) / PAGE_SIZE;

    let _ = crate::memory::phys::free_contiguous(guard_low.address, total_pages);
}
