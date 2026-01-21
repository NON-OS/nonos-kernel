// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

//! Parsed ACPI data structures.
//!
//! These structures contain processed information extracted from
//! raw ACPI tables for convenient access.

use alloc::vec::Vec;
use super::tables::{GenericAddress, PmProfile};

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
            lapic_address: 0xFEE0_0000, // Default LAPIC address
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
            sci_interrupt: 9, // Common default
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

#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiStats {
    pub tables_found: u32,
    pub processors_found: u32,
    pub ioapics_found: u32,
    pub overrides_found: u32,
    pub numa_nodes: u32,
    pub pcie_segments: u32,
    pub parse_errors: u32,
}

impl AcpiStats {
    pub const fn new() -> Self {
        Self {
            tables_found: 0,
            processors_found: 0,
            ioapics_found: 0,
            overrides_found: 0,
            numa_nodes: 0,
            pcie_segments: 0,
            parse_errors: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_info() {
        let proc = ProcessorInfo::new(0, 0, false, true);
        assert_eq!(proc.apic_id, 0);
        assert!(proc.enabled);
        assert!(!proc.is_x2apic);
    }

    #[test]
    fn test_numa_region_contains() {
        let region = NumaMemoryRegion {
            base: 0x1000,
            length: 0x2000,
            proximity_domain: 0,
            hot_pluggable: false,
            non_volatile: false,
        };
        assert!(region.contains(0x1000));
        assert!(region.contains(0x2000));
        assert!(!region.contains(0x3000)); // End is exclusive
        assert!(!region.contains(0x0FFF));
    }

    #[test]
    fn test_pcie_segment_config_address() {
        let seg = PcieSegment {
            base_address: 0xE000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 255,
        };

        assert_eq!(seg.config_address(0, 0, 0, 0), Some(0xE000_0000));
        assert_eq!(seg.config_address(0, 32, 0, 0), None); // Invalid device
    }

    #[test]
    fn test_acpi_data_defaults() {
        let data = AcpiData::new();
        assert_eq!(data.lapic_address, 0xFEE0_0000);
        assert!(data.has_legacy_pics);
        assert_eq!(data.processor_count(), 0);
    }

    #[test]
    fn test_irq_to_gsi() {
        let mut data = AcpiData::new();

        // Without override, IRQ == GSI
        assert_eq!(data.irq_to_gsi(0), 0);

        // Add override for IRQ 0 -> GSI 2
        data.overrides.push(InterruptOverride {
            source_irq: 0,
            gsi: 2,
            polarity: 0,
            trigger_mode: 0,
        });

        assert_eq!(data.irq_to_gsi(0), 2);
        assert_eq!(data.irq_to_gsi(1), 1); // No override
    }

    #[test]
    fn test_stats_default() {
        let stats = AcpiStats::new();
        assert_eq!(stats.tables_found, 0);
        assert_eq!(stats.processors_found, 0);
    }
}
