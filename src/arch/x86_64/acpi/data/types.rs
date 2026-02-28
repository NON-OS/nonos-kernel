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

#[derive(Debug, Clone)]
pub struct ProcessorInfo {
    pub apic_id: u32,
    pub processor_uid: u32,
    pub proximity_domain: u32,
    pub is_x2apic: bool,
    pub enabled: bool,
}

impl ProcessorInfo {
    pub fn new(apic_id: u32, processor_uid: u32, is_x2apic: bool, enabled: bool) -> Self {
        Self {
            apic_id,
            processor_uid,
            proximity_domain: 0,
            is_x2apic,
            enabled,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IoApicInfo {
    pub id: u8,
    pub address: u64,
    pub gsi_base: u32,
}

impl IoApicInfo {
    pub fn gsi_max(&self) -> u32 {
        self.gsi_base + 23
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InterruptOverride {
    pub source_irq: u8,
    pub gsi: u32,
    pub polarity: u8,
    pub trigger_mode: u8,
}

impl InterruptOverride {
    pub fn is_active_low(&self) -> bool {
        self.polarity == 3
    }

    pub fn is_level_triggered(&self) -> bool {
        self.trigger_mode == 3
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NmiConfig {
    pub processor_uid: u32,
    pub lint: u8,
    pub flags: u16,
}

impl NmiConfig {
    pub fn applies_to_all(&self) -> bool {
        self.processor_uid == u32::MAX
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NumaMemoryRegion {
    pub base: u64,
    pub length: u64,
    pub proximity_domain: u32,
    pub hot_pluggable: bool,
    pub non_volatile: bool,
}

impl NumaMemoryRegion {
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.length)
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PcieSegment {
    pub base_address: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl PcieSegment {
    pub fn config_address(&self, bus: u8, device: u8, function: u8, offset: u16) -> Option<u64> {
        if bus < self.start_bus || bus > self.end_bus {
            return None;
        }
        if device >= 32 || function >= 8 || offset >= 4096 {
            return None;
        }

        let addr = self.base_address
            + ((bus as u64) << 20)
            + ((device as u64) << 15)
            + ((function as u64) << 12)
            + (offset as u64);

        Some(addr)
    }
}
