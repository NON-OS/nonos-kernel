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

#[cfg(test)]
mod tests {
    use super::super::*;
    use core::mem;
    // Error Type Tests
    #[test]
    fn test_error_messages_complete() {
        let errors = [
            error::AcpiError::NotInitialized,
            error::AcpiError::AlreadyInitialized,
            error::AcpiError::RsdpNotFound,
            error::AcpiError::InvalidRsdpSignature,
            error::AcpiError::RsdpChecksumFailed,
            error::AcpiError::ExtendedRsdpChecksumFailed,
            error::AcpiError::NoRootTable,
            error::AcpiError::InvalidRsdtSignature,
            error::AcpiError::RsdtChecksumFailed,
            error::AcpiError::InvalidXsdtSignature,
            error::AcpiError::XsdtChecksumFailed,
            error::AcpiError::TableNotFound,
            error::AcpiError::InvalidTableSignature,
            error::AcpiError::TableChecksumFailed,
            error::AcpiError::InvalidTableStructure,
            error::AcpiError::FadtNotFound,
            error::AcpiError::MadtNotFound,
            error::AcpiError::PowerStateNotSupported,
            error::AcpiError::HardwareAccessFailed,
            error::AcpiError::ResetNotAvailable,
            error::AcpiError::InvalidAddress,
            error::AcpiError::UnsupportedRevision,
        ];

        for err in &errors {
            assert!(!err.as_str().is_empty());
        }
    }

    // Table Structure Size Tests

    #[test]
    fn test_rsdp_structure_sizes() {
        assert_eq!(mem::size_of::<tables::Rsdp>(), 20);
        assert_eq!(mem::size_of::<tables::RsdpExtended>(), 36);
    }

    #[test]
    fn test_sdt_header_size() {
        assert_eq!(mem::size_of::<tables::SdtHeader>(), 36);
    }

    #[test]
    fn test_generic_address_size() {
        assert_eq!(mem::size_of::<tables::GenericAddress>(), 12);
    }

    #[test]
    fn test_madt_structure_sizes() {
        assert_eq!(mem::size_of::<tables::Madt>(), 44);
        assert_eq!(mem::size_of::<tables::MadtEntryHeader>(), 2);
        assert_eq!(mem::size_of::<tables::MadtLocalApic>(), 8);
        assert_eq!(mem::size_of::<tables::MadtIoApic>(), 12);
        assert_eq!(mem::size_of::<tables::MadtInterruptOverride>(), 10);
        assert_eq!(mem::size_of::<tables::MadtLocalApicNmi>(), 6);
        assert_eq!(mem::size_of::<tables::MadtLocalApicOverride>(), 12);
        assert_eq!(mem::size_of::<tables::MadtLocalX2Apic>(), 16);
        assert_eq!(mem::size_of::<tables::MadtLocalX2ApicNmi>(), 12);
    }

    #[test]
    fn test_hpet_structure_size() {
        assert_eq!(mem::size_of::<tables::Hpet>(), 56);
    }

    #[test]
    fn test_mcfg_structure_sizes() {
        assert_eq!(mem::size_of::<tables::Mcfg>(), 44);
        assert_eq!(mem::size_of::<tables::McfgEntry>(), 16);
    }

    #[test]
    fn test_srat_structure_sizes() {
        assert_eq!(mem::size_of::<tables::Srat>(), 48);
        assert_eq!(mem::size_of::<tables::SratProcessorAffinity>(), 16);
        assert_eq!(mem::size_of::<tables::SratMemoryAffinity>(), 40);
        assert_eq!(mem::size_of::<tables::SratX2ApicAffinity>(), 24);
    }

    #[test]
    fn test_slit_structure_size() {
        assert_eq!(mem::size_of::<tables::Slit>(), 44);
    }

    // Table Signature Tests

    #[test]
    fn test_table_signatures() {
        assert_eq!(tables::SIG_RSDT, u32::from_le_bytes(*b"RSDT"));
        assert_eq!(tables::SIG_XSDT, u32::from_le_bytes(*b"XSDT"));
        assert_eq!(tables::SIG_FADT, u32::from_le_bytes(*b"FACP"));
        assert_eq!(tables::SIG_MADT, u32::from_le_bytes(*b"APIC"));
        assert_eq!(tables::SIG_HPET, u32::from_le_bytes(*b"HPET"));
        assert_eq!(tables::SIG_MCFG, u32::from_le_bytes(*b"MCFG"));
        assert_eq!(tables::SIG_SRAT, u32::from_le_bytes(*b"SRAT"));
        assert_eq!(tables::SIG_SLIT, u32::from_le_bytes(*b"SLIT"));
    }

    #[test]
    fn test_rsdp_signature() {
        assert_eq!(&tables::RSDP_SIGNATURE, b"RSD PTR ");
    }

    // PM Profile Tests

    #[test]
    fn test_pm_profile_values() {
        assert_eq!(tables::PmProfile::Unspecified as u8, 0);
        assert_eq!(tables::PmProfile::Desktop as u8, 1);
        assert_eq!(tables::PmProfile::Mobile as u8, 2);
        assert_eq!(tables::PmProfile::Workstation as u8, 3);
        assert_eq!(tables::PmProfile::EnterpriseServer as u8, 4);
    }

    #[test]
    fn test_pm_profile_from_u8() {
        assert_eq!(tables::PmProfile::from_u8(1), tables::PmProfile::Desktop);
        assert_eq!(tables::PmProfile::from_u8(4), tables::PmProfile::EnterpriseServer);
        assert_eq!(tables::PmProfile::from_u8(255), tables::PmProfile::Unspecified);
    }

    #[test]
    fn test_pm_profile_classification() {
        assert!(tables::PmProfile::EnterpriseServer.is_server());
        assert!(tables::PmProfile::SohoServer.is_server());
        assert!(!tables::PmProfile::Desktop.is_server());

        assert!(tables::PmProfile::Mobile.is_mobile());
        assert!(tables::PmProfile::Tablet.is_mobile());
        assert!(!tables::PmProfile::Desktop.is_mobile());
    }

    // MADT Entry Type Tests

    #[test]
    fn test_madt_entry_types() {
        assert_eq!(tables::MadtEntryType::LocalApic as u8, 0);
        assert_eq!(tables::MadtEntryType::IoApic as u8, 1);
        assert_eq!(tables::MadtEntryType::InterruptSourceOverride as u8, 2);
        assert_eq!(tables::MadtEntryType::LocalX2Apic as u8, 9);
        assert_eq!(tables::MadtEntryType::LocalX2ApicNmi as u8, 10);
    }

    #[test]
    fn test_madt_entry_type_from_u8() {
        assert_eq!(
            tables::MadtEntryType::from_u8(0),
            Some(tables::MadtEntryType::LocalApic)
        );
        assert_eq!(
            tables::MadtEntryType::from_u8(9),
            Some(tables::MadtEntryType::LocalX2Apic)
        );
        assert_eq!(tables::MadtEntryType::from_u8(99), None);
    }

    // SRAT Entry Type Tests

    #[test]
    fn test_srat_entry_types() {
        assert_eq!(tables::SratEntryType::ProcessorAffinity as u8, 0);
        assert_eq!(tables::SratEntryType::MemoryAffinity as u8, 1);
        assert_eq!(tables::SratEntryType::ProcessorX2ApicAffinity as u8, 2);
    }

    // Address Space Tests

    #[test]
    fn test_address_space_values() {
        assert_eq!(tables::AddressSpace::SystemMemory as u8, 0);
        assert_eq!(tables::AddressSpace::SystemIo as u8, 1);
        assert_eq!(tables::AddressSpace::PciConfig as u8, 2);
        assert_eq!(tables::AddressSpace::FunctionalFixedHw as u8, 0x7F);
    }

    #[test]
    fn test_address_space_from_u8() {
        assert_eq!(
            tables::AddressSpace::from_u8(0),
            Some(tables::AddressSpace::SystemMemory)
        );
        assert_eq!(
            tables::AddressSpace::from_u8(1),
            Some(tables::AddressSpace::SystemIo)
        );
        assert_eq!(tables::AddressSpace::from_u8(0xFF), None);
    }

    // Sleep State Tests

    #[test]
    fn test_sleep_state_values() {
        assert_eq!(power::SleepState::S0 as u8, 0);
        assert_eq!(power::SleepState::S3 as u8, 3);
        assert_eq!(power::SleepState::S5 as u8, 5);
    }

    #[test]
    fn test_sleep_state_names() {
        assert!(!power::SleepState::S0.name().is_empty());
        assert!(!power::SleepState::S5.name().is_empty());
        assert!(power::SleepState::S3.name().contains("RAM"));
    }

    // Data Structure Tests

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

        // Invalid parameters
        assert_eq!(seg.config_address(0, 32, 0, 0), None); // device >= 32
        assert_eq!(seg.config_address(0, 0, 8, 0), None); // function >= 8
        assert_eq!(seg.config_address(0, 0, 0, 4096), None); // offset >= 4096
    }

    #[test]
    fn test_irq_to_gsi() {
        let mut data = data::AcpiData::new();

        // Without override
        assert_eq!(data.irq_to_gsi(0), 0);
        assert_eq!(data.irq_to_gsi(1), 1);

        // Add override
        data.overrides.push(data::InterruptOverride {
            source_irq: 0,
            gsi: 2,
            polarity: 3,
            trigger_mode: 3,
        });

        assert_eq!(data.irq_to_gsi(0), 2);
        assert_eq!(data.irq_to_gsi(1), 1); // No override
    }

    // Statistics Tests

    #[test]
    fn test_stats_default() {
        let stats = data::AcpiStats::new();
        assert_eq!(stats.tables_found, 0);
        assert_eq!(stats.processors_found, 0);
        assert_eq!(stats.ioapics_found, 0);
        assert_eq!(stats.parse_errors, 0);
    }

    // Device Tests

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

    // FADT Flags Tests

    #[test]
    fn test_fadt_flags() {
        assert_eq!(tables::fadt_flags::WBINVD, 1 << 0);
        assert_eq!(tables::fadt_flags::RESET_REG_SUP, 1 << 10);
        assert_eq!(tables::fadt_flags::HW_REDUCED_ACPI, 1 << 20);
        assert_eq!(tables::fadt_flags::TMR_VAL_EXT, 1 << 8);
    }

    // MADT Flags Tests

    #[test]
    fn test_madt_flags() {
        assert_eq!(tables::madt_flags::PCAT_COMPAT, 1);
    }

    // HPET Register Tests

    #[test]
    fn test_hpet_registers() {
        assert_eq!(tables::hpet::registers::GCAP_ID, 0x000);
        assert_eq!(tables::hpet::registers::GCONF, 0x010);
        assert_eq!(tables::hpet::registers::MAIN_CNT, 0x0F0);
        assert_eq!(tables::hpet::registers::timer_config(0), 0x100);
        assert_eq!(tables::hpet::registers::timer_config(1), 0x120);
    }

    // SLIT Distance Tests

    #[test]
    fn test_slit_constants() {
        assert_eq!(tables::Slit::LOCAL_DISTANCE, 10);
        assert_eq!(tables::Slit::UNREACHABLE, 255);
    }

    #[test]
    fn test_numa_distances_simple() {
        let distances = tables::slit::NumaDistances::new_simple(4, 20);
        assert_eq!(distances.node_count, 4);

        // Local distances should be 10
        for i in 0..4 {
            assert_eq!(distances.distance(i, i), Some(10));
        }

        // Remote distances should be 20
        assert_eq!(distances.distance(0, 1), Some(20));
        assert_eq!(distances.distance(1, 0), Some(20));
    }

    #[test]
    fn test_pcie_config_offsets() {
        assert_eq!(tables::mcfg::config_offsets::VENDOR_ID, 0x00);
        assert_eq!(tables::mcfg::config_offsets::DEVICE_ID, 0x02);
        assert_eq!(tables::mcfg::config_offsets::COMMAND, 0x04);
        assert_eq!(tables::mcfg::config_offsets::BAR0, 0x10);
        assert_eq!(tables::mcfg::config_offsets::CAP_PTR, 0x34);
    }

    #[test]
    fn test_pcie_command_bits() {
        assert_eq!(tables::mcfg::command_bits::IO_SPACE, 1 << 0);
        assert_eq!(tables::mcfg::command_bits::MEMORY_SPACE, 1 << 1);
        assert_eq!(tables::mcfg::command_bits::BUS_MASTER, 1 << 2);
    }
}
