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
    use crate::arch::x86_64::acpi::{tables, power};

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

    #[test]
    fn test_srat_entry_types() {
        assert_eq!(tables::SratEntryType::ProcessorAffinity as u8, 0);
        assert_eq!(tables::SratEntryType::MemoryAffinity as u8, 1);
        assert_eq!(tables::SratEntryType::ProcessorX2ApicAffinity as u8, 2);
    }

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
}
