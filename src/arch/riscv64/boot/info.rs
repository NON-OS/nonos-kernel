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

use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct BootInfo {
    pub ram_base: u64,
    pub ram_size: u64,
    pub kernel_base: u64,
    pub kernel_size: u64,
    pub dtb_base: u64,
    pub dtb_size: u64,
    pub uart_base: u64,
    pub plic_base: u64,
    pub clint_base: u64,
    pub hart_count: u32,
    pub boot_hart: u32,
    pub memory_regions: Vec<MemoryRegion>,
}

impl Default for BootInfo {
    fn default() -> Self {
        Self {
            ram_base: 0x8000_0000,
            ram_size: 0x1_0000_0000,
            kernel_base: 0x8020_0000,
            kernel_size: 0x0020_0000,
            dtb_base: 0,
            dtb_size: 0,
            uart_base: 0x1000_0000,
            // Zero means "no PLIC was published by the DTB". boot::init
            // skips `plic::init_plic` and `plic_present()` stays false,
            // so the IRQ broker refuses every bind on ACLINT-only boards.
            plic_base: 0,
            clint_base: 0x0200_0000,
            hart_count: 1,
            boot_hart: 0,
            memory_regions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub region_type: MemoryType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Available,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    Unusable,
    Kernel,
    DeviceMemory,
}

impl BootInfo {
    pub fn total_memory(&self) -> u64 {
        self.memory_regions
            .iter()
            .filter(|r| r.region_type == MemoryType::Available)
            .map(|r| r.size)
            .sum()
    }

    pub fn add_memory_region(&mut self, base: u64, size: u64, region_type: MemoryType) {
        self.memory_regions.push(MemoryRegion { base, size, region_type });
    }

    pub fn usable_memory_start(&self) -> u64 {
        self.kernel_base + self.kernel_size
    }

    pub fn usable_memory_size(&self) -> u64 {
        let end = self.ram_base + self.ram_size;
        let start = self.usable_memory_start();
        end.saturating_sub(start)
    }
}
