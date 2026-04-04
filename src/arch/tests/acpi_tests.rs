// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for arch/x86_64/acpi

use crate::arch::x86_64::acpi::{
    SIG_FADT, SIG_HPET, SIG_MADT, SIG_MCFG, SIG_RSDT, SIG_SLIT, SIG_SRAT, SIG_XSDT,
    RSDP_ALIGNMENT, RSDP_SIGNATURE, PmProfile, MadtEntryType, SratEntryType, AddressSpace,
};

#[test_case]
fn test_table_signatures() {
    assert_eq!(SIG_FADT, *b"FACP");
    assert_eq!(SIG_HPET, *b"HPET");
    assert_eq!(SIG_MADT, *b"APIC");
    assert_eq!(SIG_MCFG, *b"MCFG");
    assert_eq!(SIG_RSDT, *b"RSDT");
    assert_eq!(SIG_XSDT, *b"XSDT");
    assert_eq!(SIG_SRAT, *b"SRAT");
    assert_eq!(SIG_SLIT, *b"SLIT");
}

#[test_case]
fn test_rsdp_signature() {
    assert_eq!(RSDP_SIGNATURE, *b"RSD PTR ");
}

#[test_case]
fn test_rsdp_alignment() {
    assert_eq!(RSDP_ALIGNMENT, 16);
}

#[test_case]
fn test_pm_profile_variants() {
    assert_eq!(PmProfile::Unspecified as u8, 0);
    assert_eq!(PmProfile::Desktop as u8, 1);
    assert_eq!(PmProfile::Mobile as u8, 2);
    assert_eq!(PmProfile::Workstation as u8, 3);
    assert_eq!(PmProfile::EnterpriseServer as u8, 4);
    assert_eq!(PmProfile::SohoServer as u8, 5);
    assert_eq!(PmProfile::AppliancePc as u8, 6);
    assert_eq!(PmProfile::PerformanceServer as u8, 7);
    assert_eq!(PmProfile::Tablet as u8, 8);
}

#[test_case]
fn test_madt_entry_types() {
    assert_eq!(MadtEntryType::LocalApic as u8, 0);
    assert_eq!(MadtEntryType::IoApic as u8, 1);
    assert_eq!(MadtEntryType::InterruptOverride as u8, 2);
    assert_eq!(MadtEntryType::NmiSource as u8, 3);
    assert_eq!(MadtEntryType::LocalApicNmi as u8, 4);
    assert_eq!(MadtEntryType::LocalApicOverride as u8, 5);
    assert_eq!(MadtEntryType::LocalX2Apic as u8, 9);
    assert_eq!(MadtEntryType::LocalX2ApicNmi as u8, 10);
}

#[test_case]
fn test_srat_entry_types() {
    assert_eq!(SratEntryType::ProcessorAffinity as u8, 0);
    assert_eq!(SratEntryType::MemoryAffinity as u8, 1);
    assert_eq!(SratEntryType::X2ApicAffinity as u8, 2);
}

#[test_case]
fn test_address_space_variants() {
    assert_eq!(AddressSpace::SystemMemory as u8, 0);
    assert_eq!(AddressSpace::SystemIo as u8, 1);
    assert_eq!(AddressSpace::PciConfig as u8, 2);
    assert_eq!(AddressSpace::EmbeddedController as u8, 3);
    assert_eq!(AddressSpace::SmBus as u8, 4);
    assert_eq!(AddressSpace::Cmos as u8, 5);
    assert_eq!(AddressSpace::PciBar as u8, 6);
    assert_eq!(AddressSpace::Ipmi as u8, 7);
    assert_eq!(AddressSpace::GeneralIo as u8, 8);
    assert_eq!(AddressSpace::FunctionalFixed as u8, 0x7F);
}

#[test_case]
fn test_signatures_are_4_bytes() {
    assert_eq!(SIG_FADT.len(), 4);
    assert_eq!(SIG_HPET.len(), 4);
    assert_eq!(SIG_MADT.len(), 4);
    assert_eq!(SIG_MCFG.len(), 4);
    assert_eq!(SIG_RSDT.len(), 4);
    assert_eq!(SIG_XSDT.len(), 4);
}

#[test_case]
fn test_rsdp_signature_is_8_bytes() {
    assert_eq!(RSDP_SIGNATURE.len(), 8);
}

#[test_case]
fn test_rsdp_alignment_power_of_two() {
    assert!(RSDP_ALIGNMENT.is_power_of_two());
}
