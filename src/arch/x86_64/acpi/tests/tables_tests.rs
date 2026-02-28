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
    use crate::arch::x86_64::acpi::tables;
    use core::mem;

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
}
