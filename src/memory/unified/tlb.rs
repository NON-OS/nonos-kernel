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

use super::super::layout;
use super::super::paging::manager;
use crate::memory::addr::VirtAddr;

#[inline]
pub fn flush_tlb_range(start: VirtAddr, size: usize) {
    let pages = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    for i in 0..pages {
        let page_va = VirtAddr::new(start.as_u64() + (i * layout::PAGE_SIZE) as u64);
        manager::invalidate_page(page_va);
    }
}

#[inline]
pub fn flush_tlb_all() {
    manager::invalidate_all_pages();
}
