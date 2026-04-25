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

use super::super::types::{GuardRegion, GuardType};
use crate::memory::layout;
use alloc::vec::Vec;

pub fn get_guard_regions() -> Vec<GuardRegion> {
    let mut guards = Vec::new();

    for region in layout::get_all_stack_regions() {
        guards.push(GuardRegion {
            start: region.base - region.guard_size as u64,
            end: region.base,
            region_type: GuardType::StackGuard,
        });
        guards.push(GuardRegion {
            start: region.base + region.size as u64,
            end: region.base + region.size as u64 + region.guard_size as u64,
            region_type: GuardType::StackGuard,
        });
    }

    guards.push(GuardRegion {
        start: layout::KHEAP_BASE - layout::PAGE_SIZE as u64,
        end: layout::KHEAP_BASE,
        region_type: GuardType::HeapGuard,
    });
    guards.push(GuardRegion {
        start: layout::KHEAP_BASE + layout::KHEAP_SIZE,
        end: layout::KHEAP_BASE + layout::KHEAP_SIZE + layout::PAGE_SIZE as u64,
        region_type: GuardType::HeapGuard,
    });

    guards
}
