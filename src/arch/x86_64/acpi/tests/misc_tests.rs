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
    use crate::arch::x86_64::acpi::{error, tables};

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

    #[test]
    fn test_fadt_flags() {
        assert_eq!(tables::fadt_flags::WBINVD, 1 << 0);
        assert_eq!(tables::fadt_flags::RESET_REG_SUP, 1 << 10);
        assert_eq!(tables::fadt_flags::HW_REDUCED_ACPI, 1 << 20);
        assert_eq!(tables::fadt_flags::TMR_VAL_EXT, 1 << 8);
    }

    #[test]
    fn test_madt_flags() {
        assert_eq!(tables::madt_flags::PCAT_COMPAT, 1);
    }

    #[test]
    fn test_hpet_registers() {
        assert_eq!(tables::hpet::registers::GCAP_ID, 0x000);
        assert_eq!(tables::hpet::registers::GCONF, 0x010);
        assert_eq!(tables::hpet::registers::MAIN_CNT, 0x0F0);
        assert_eq!(tables::hpet::registers::timer_config(0), 0x100);
        assert_eq!(tables::hpet::registers::timer_config(1), 0x120);
    }

    #[test]
    fn test_slit_constants() {
        assert_eq!(tables::Slit::LOCAL_DISTANCE, 10);
        assert_eq!(tables::Slit::UNREACHABLE, 255);
    }

    #[test]
    fn test_numa_distances_simple() {
        let distances = tables::slit::NumaDistances::new_simple(4, 20);
        assert_eq!(distances.node_count, 4);

        for i in 0..4 {
            assert_eq!(distances.distance(i, i), Some(10));
        }

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
