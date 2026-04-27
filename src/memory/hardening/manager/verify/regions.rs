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

extern crate alloc;

use crate::memory::{dma, layout, mmio, safety};
use x86_64::VirtAddr;

pub fn get_all_process_regions() -> alloc::vec::Vec<(VirtAddr, usize)> {
    let mut regions = alloc::vec::Vec::new();
    let kernel_sections = layout::kernel_sections();
    for section in &kernel_sections {
        regions.push((VirtAddr::new(section.start), section.size() as usize));
    }
    if let Ok(heap_base) = layout::heap_base_for(0) {
        regions.push((VirtAddr::new(heap_base), layout::KHEAP_SIZE as usize));
    }
    for region in layout::get_all_stack_regions() {
        regions.push((VirtAddr::new(region.base), region.size));
    }
    for region in layout::get_percpu_regions() {
        regions.push((VirtAddr::new(region.base), region.size));
    }
    for region in mmio::get_mapped_regions() {
        regions.push((region.va, region.size));
    }
    for region in dma::get_allocated_regions() {
        regions.push((region.virt_addr, region.size));
    }
    for region in layout::get_module_regions() {
        regions.push((VirtAddr::new(region.base), region.size));
    }
    for region in safety::get_guard_regions() {
        regions.push((VirtAddr::new(region.start), (region.end - region.start) as usize));
    }
    regions.sort_by_key(|&(addr, _)| addr.as_u64());
    regions.dedup_by(|a, b| {
        let a_end = a.0.as_u64() + a.1 as u64;
        let b_start = b.0.as_u64();
        a_end > b_start && a.0.as_u64() <= b_start
    });
    regions
}
