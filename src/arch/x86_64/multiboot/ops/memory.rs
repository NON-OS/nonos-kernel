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

use super::super::error::MultibootError;
use super::super::platform::Platform;
use super::super::state::MULTIBOOT_MANAGER;

pub fn get_safe_memory_regions() -> Result<Vec<crate::memory::layout::Region>, MultibootError> {
    if !MULTIBOOT_MANAGER.is_initialized() {
        return Err(MultibootError::NotInitialized);
    }

    let memory_map = MULTIBOOT_MANAGER.memory_map();
    if memory_map.is_empty() {
        return Err(MultibootError::NoMemoryMap);
    }

    let mut regions = Vec::new();

    for entry in &memory_map {
        if entry.is_available() && entry.length >= 4096 && entry.base_addr >= 0x100000 {
            regions.push(crate::memory::layout::Region {
                start: entry.base_addr,
                end: entry.base_addr.saturating_add(entry.length),
                kind: crate::memory::layout::RegionKind::Usable,
            });
        } else if entry.is_acpi_reclaimable() {
            regions.push(crate::memory::layout::Region {
                start: entry.base_addr,
                end: entry.base_addr.saturating_add(entry.length),
                kind: crate::memory::layout::RegionKind::Acpi,
            });
        }
    }

    regions.sort_by_key(|r| r.start);

    Ok(regions)
}

pub fn get_fallback_memory_regions(platform: Platform) -> Vec<crate::memory::layout::Region> {
    let end = match platform {
        Platform::QemuTcg | Platform::QemuKvm => 0x8000000,
        Platform::Kvm | Platform::Vmware | Platform::VirtualBox => 0x10000000,
        Platform::HyperV => 0x20000000,
        Platform::BareMetal => 0x4000000,
        _ => 0x4000000,
    };

    vec![crate::memory::layout::Region {
        start: 0x100000,
        end,
        kind: crate::memory::layout::RegionKind::Usable,
    }]
}
