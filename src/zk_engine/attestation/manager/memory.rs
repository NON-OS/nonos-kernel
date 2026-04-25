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

use super::super::types::MemoryLayout;
use super::types::AttestationManager;
use crate::memory::layout;
use crate::memory::VirtAddr;
use crate::zk_engine::ZKError;

pub(super) fn measure_memory_layout(_mgr: &AttestationManager) -> Result<MemoryLayout, ZKError> {
    let sections = layout::kernel_sections();
    let kernel_start = sections.iter().map(|s| s.start).min().unwrap_or(layout::KERNEL_BASE);
    let kernel_end = sections.iter().map(|s| s.end).max().unwrap_or(layout::KERNEL_BASE);
    let layout_config = layout::get_layout();
    let heap_base = layout_config.heap_lo;
    let heap_size = layout_config.heap_sz;
    Ok(MemoryLayout {
        kernel_start: VirtAddr::new(kernel_start),
        kernel_end: VirtAddr::new(kernel_end),
        user_start: VirtAddr::new(layout::USER_BASE),
        user_end: VirtAddr::new(layout::USER_TOP),
        heap_start: VirtAddr::new(heap_base),
        heap_end: VirtAddr::new(heap_base + heap_size),
    })
}
