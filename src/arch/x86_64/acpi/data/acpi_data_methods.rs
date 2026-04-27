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

use super::acpi_data_struct::AcpiData;
use super::interrupt::InterruptOverride;
use super::ioapic::IoApicInfo;

impl AcpiData {
    pub fn processor_count(&self) -> usize {
        self.processors.len()
    }

    pub fn enabled_processor_count(&self) -> usize {
        self.processors.iter().filter(|p| p.enabled).count()
    }

    pub fn bsp_apic_id(&self) -> Option<u32> {
        self.processors.first().map(|p| p.apic_id)
    }

    pub fn find_ioapic_for_gsi(&self, gsi: u32) -> Option<&IoApicInfo> {
        self.ioapics.iter().find(|io| gsi >= io.gsi_base && gsi < io.gsi_base + 24)
    }

    pub fn find_override(&self, irq: u8) -> Option<&InterruptOverride> {
        self.overrides.iter().find(|o| o.source_irq == irq)
    }

    pub fn irq_to_gsi(&self, irq: u8) -> u32 {
        self.find_override(irq).map(|o| o.gsi).unwrap_or(irq as u32)
    }

    pub fn find_numa_node(&self, addr: u64) -> Option<u32> {
        self.numa_regions.iter().find(|r| r.contains(addr)).map(|r| r.proximity_domain)
    }
}
