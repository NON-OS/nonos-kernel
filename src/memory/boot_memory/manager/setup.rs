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

use super::super::constants::*;
use super::super::error::BootMemoryResult;
use super::super::types::{BootHandoff, MemoryRegion, RegionType};
use super::helpers::{align_down, align_up};
use super::state::BootMemoryManager;

impl BootMemoryManager {
    pub(super) fn setup_regions_from_handoff(
        &mut self,
        handoff: &BootHandoff,
    ) -> BootMemoryResult<()> {
        self.regions.clear();
        self.add_region(
            CONVENTIONAL_MEMORY_START,
            CONVENTIONAL_MEMORY_END,
            RegionType::Reserved,
            0,
        );

        if handoff.kernel_size > 0 {
            self.add_region(
                handoff.kernel_base,
                handoff.kernel_base.saturating_add(handoff.kernel_size),
                RegionType::Kernel,
                0,
            );
        }
        if handoff.capsule_size > 0 {
            self.add_region(
                handoff.capsule_base,
                handoff.capsule_base.saturating_add(handoff.capsule_size),
                RegionType::Capsule,
                0,
            );
        }
        if handoff.memory_size > 0 {
            let start = align_up(handoff.memory_base, PAGE_SIZE_U64);
            let end =
                align_down(handoff.memory_base.saturating_add(handoff.memory_size), PAGE_SIZE_U64);
            if end > start {
                self.add_region(start, end, RegionType::Available, 0);
            }
        }

        self.add_hardware_regions();
        self.sort_regions();
        self.find_next_free()?;
        self.calculate_totals();
        Ok(())
    }

    pub(super) fn add_hardware_regions(&mut self) {
        self.add_region(VGA_TEXT_START, VGA_TEXT_END, RegionType::Hardware, REGION_FLAG_UNCACHED);
        self.add_region(
            LEGACY_VIDEO_START,
            LEGACY_VIDEO_END,
            RegionType::Hardware,
            REGION_FLAG_UNCACHED,
        );
        self.add_region(
            PCI_CONFIG_START,
            PCI_CONFIG_END,
            RegionType::Hardware,
            REGION_FLAG_UNCACHED,
        );
        self.add_region(
            IOAPIC_BASE,
            IOAPIC_BASE + IOAPIC_SIZE,
            RegionType::Hardware,
            REGION_FLAG_UNCACHED,
        );
        self.add_region(
            LAPIC_BASE,
            LAPIC_BASE + LAPIC_SIZE,
            RegionType::Hardware,
            REGION_FLAG_UNCACHED,
        );
    }

    pub(super) fn add_region(&mut self, start: u64, end: u64, region_type: RegionType, flags: u32) {
        if start >= end || self.regions.len() >= MAX_BOOT_REGIONS {
            return;
        }
        self.regions.push(MemoryRegion::new(start, end, region_type, flags));
    }

    pub(super) fn sort_regions(&mut self) {
        self.regions.sort_by_key(|r| r.start.as_u64());
    }
}
