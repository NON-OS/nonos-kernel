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

use alloc::vec::Vec;

use super::super::types::MultibootInfo;
use super::types::Platform;

pub fn get_safe_memory_regions(
    platform: Platform,
    multiboot_info: &MultibootInfo,
) -> Vec<crate::memory::layout::Region> {
    let mut regions = Vec::new();

    for entry in &multiboot_info.memory_map {
        if entry.is_available() && entry.length >= 4096 && entry.base_addr >= 0x10_0000 {
            regions.push(crate::memory::layout::Region {
                start: entry.base_addr,
                end: entry.base_addr.saturating_add(entry.length),
                kind: crate::memory::layout::RegionKind::Usable,
            });
        }
    }

    if regions.is_empty() {
        let (start, end) = match platform {
            Platform::Qemu => (0x10_0000, 0x800_0000),
            Platform::VirtualMachine => (0x10_0000, 0x400_0000),
            Platform::BareMetal => (0x10_0000, 0x200_0000),
        };

        regions.push(crate::memory::layout::Region {
            start,
            end,
            kind: crate::memory::layout::RegionKind::Usable,
        });
    }

    regions
}
