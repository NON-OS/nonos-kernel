// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::api::VMEM_STATS;
use crate::memory::{layout, paging};
use crate::memory::addr::VirtAddr;

pub fn flush_tlb_range(start: VirtAddr, size: usize) {
    let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    for i in 0..page_count {
        let va = VirtAddr::new(start.as_u64() + (i * layout::PAGE_SIZE) as u64);
        paging::invalidate_page(va);
    }
    VMEM_STATS.record_tlb_shootdowns(page_count as u64);
}

pub fn flush_all_tlb() {
    paging::invalidate_all_pages();
    VMEM_STATS.record_tlb_shootdowns(1);
}
