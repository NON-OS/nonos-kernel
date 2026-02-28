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

#[cfg(test)]
mod tests {
    use crate::arch::x86_64::acpi::{data, devices};

    #[test]
    fn test_acpi_data_defaults() {
        let data = data::AcpiData::new();
        assert_eq!(data.lapic_address, 0xFEE0_0000);
        assert!(data.has_legacy_pics);
        assert_eq!(data.processor_count(), 0);
        assert_eq!(data.enabled_processor_count(), 0);
    }

    #[test]
    fn test_processor_info() {
        let proc = data::ProcessorInfo::new(0, 0, false, true);
        assert_eq!(proc.apic_id, 0);
        assert!(proc.enabled);
        assert!(!proc.is_x2apic);
        assert_eq!(proc.proximity_domain, 0);
    }

    #[test]
    fn test_numa_region_contains() {
        let region = data::NumaMemoryRegion {
            base: 0x1000,
            length: 0x2000,
            proximity_domain: 0,
            hot_pluggable: false,
            non_volatile: false,
        };
        assert!(region.contains(0x1000));
        assert!(region.contains(0x2FFF));
        assert!(!region.contains(0x3000));
        assert!(!region.contains(0x0FFF));
    }

    #[test]
    fn test_pcie_segment_config_address() {
        let seg = data::PcieSegment {
            base_address: 0xE000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 255,
        };

        assert_eq!(seg.config_address(0, 0, 0, 0), Some(0xE000_0000));
        assert_eq!(seg.config_address(1, 0, 0, 0), Some(0xE010_0000));
        assert_eq!(seg.config_address(0, 1, 0, 0), Some(0xE000_8000));
        assert_eq!(seg.config_address(0, 0, 1, 0), Some(0xE000_1000));

        assert_eq!(seg.config_address(0, 32, 0, 0), None);
        assert_eq!(seg.config_address(0, 0, 8, 0), None);
        assert_eq!(seg.config_address(0, 0, 0, 4096), None);
    }

    #[test]
    fn test_irq_to_gsi() {
        let mut data = data::AcpiData::new();

        assert_eq!(data.irq_to_gsi(0), 0);
        assert_eq!(data.irq_to_gsi(1), 1);

        data.overrides.push(data::InterruptOverride {
            source_irq: 0,
            gsi: 2,
            polarity: 3,
            trigger_mode: 3,
        });

        assert_eq!(data.irq_to_gsi(0), 2);
        assert_eq!(data.irq_to_gsi(1), 1);
    }

    #[test]
    fn test_stats_default() {
        let stats = data::AcpiStats::new();
        assert_eq!(stats.tables_found, 0);
        assert_eq!(stats.processors_found, 0);
        assert_eq!(stats.ioapics_found, 0);
        assert_eq!(stats.parse_errors, 0);
    }

    #[test]
    fn test_pci_device_bdf() {
        let dev = devices::PciDevice {
            segment: 0,
            bus: 1,
            device: 2,
            function: 3,
            vendor_id: 0,
            device_id: 0,
            class: 0,
            subclass: 0,
        };
        assert_eq!(dev.bdf(), (1 << 8) | (2 << 3) | 3);
    }

    #[test]
    fn test_pci_device_class_detection() {
        assert!(devices::PciDevice {
            segment: 0, bus: 0, device: 0, function: 0,
            vendor_id: 0, device_id: 0,
            class: 0x06, subclass: 0,
        }.is_bridge());

        assert!(devices::PciDevice {
            segment: 0, bus: 0, device: 0, function: 0,
            vendor_id: 0, device_id: 0,
            class: 0x01, subclass: 0,
        }.is_storage());

        assert!(devices::PciDevice {
            segment: 0, bus: 0, device: 0, function: 0,
            vendor_id: 0, device_id: 0,
            class: 0x02, subclass: 0,
        }.is_network());

        assert!(devices::PciDevice {
            segment: 0, bus: 0, device: 0, function: 0,
            vendor_id: 0, device_id: 0,
            class: 0x03, subclass: 0,
        }.is_display());
    }
}
