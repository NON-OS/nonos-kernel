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

use crate::arch::x86_64::acpi::tables::{GenericAddress, PmProfile};
use super::types::{ProcessorInfo, IoApicInfo, InterruptOverride, NmiConfig, NumaMemoryRegion, PcieSegment};

#[derive(Debug)]
pub struct AcpiData {
    pub revision: u8,
    pub oem_id: [u8; 6],
    pub lapic_address: u64,
    pub has_legacy_pics: bool,
    pub processors: Vec<ProcessorInfo>,
    pub ioapics: Vec<IoApicInfo>,
    pub overrides: Vec<InterruptOverride>,
    pub nmis: Vec<NmiConfig>,
    pub numa_regions: Vec<NumaMemoryRegion>,
    pub pcie_segments: Vec<PcieSegment>,
    pub hpet_address: Option<u64>,
    pub pm1a_control: u32,
    pub pm1b_control: u32,
    pub slp_typ: [u8; 6],
    pub reset_reg: Option<GenericAddress>,
    pub reset_value: u8,
    pub pm_profile: PmProfile,
    pub sci_interrupt: u16,
}

impl AcpiData {
    pub fn new() -> Self {
        Self {
            revision: 0,
            oem_id: [0; 6],
            lapic_address: 0xFEE0_0000,
            has_legacy_pics: true,
            processors: Vec::new(),
            ioapics: Vec::new(),
            overrides: Vec::new(),
            nmis: Vec::new(),
            numa_regions: Vec::new(),
            pcie_segments: Vec::new(),
            hpet_address: None,
            pm1a_control: 0,
            pm1b_control: 0,
            slp_typ: [0; 6],
            reset_reg: None,
            reset_value: 0,
            pm_profile: PmProfile::Unspecified,
            sci_interrupt: 9,
        }
    }

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
        self.ioapics
            .iter()
            .find(|io| gsi >= io.gsi_base && gsi < io.gsi_base + 24)
    }

    pub fn find_override(&self, irq: u8) -> Option<&InterruptOverride> {
        self.overrides.iter().find(|o| o.source_irq == irq)
    }

    pub fn irq_to_gsi(&self, irq: u8) -> u32 {
        self.find_override(irq)
            .map(|o| o.gsi)
            .unwrap_or(irq as u32)
    }

    pub fn find_numa_node(&self, addr: u64) -> Option<u32> {
        self.numa_regions
            .iter()
            .find(|r| r.contains(addr))
            .map(|r| r.proximity_domain)
    }
}

impl Default for AcpiData {
    fn default() -> Self {
        Self::new()
    }
}
