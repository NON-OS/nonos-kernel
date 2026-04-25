// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::arch::x86_64::acpi::{
    AddressSpace, MadtEntryType, PmProfile, SratEntryType, RSDP_ALIGNMENT, RSDP_SIGNATURE,
    SIG_FADT, SIG_HPET, SIG_MADT, SIG_MCFG, SIG_RSDT, SIG_SLIT, SIG_SRAT, SIG_XSDT,
};
use crate::test::framework::TestResult;

pub(crate) fn test_table_signatures() -> TestResult {
    if SIG_FADT != *b"FACP" {
        return TestResult::Fail;
    }
    if SIG_HPET != *b"HPET" {
        return TestResult::Fail;
    }
    if SIG_MADT != *b"APIC" {
        return TestResult::Fail;
    }
    if SIG_MCFG != *b"MCFG" {
        return TestResult::Fail;
    }
    if SIG_RSDT != *b"RSDT" {
        return TestResult::Fail;
    }
    if SIG_XSDT != *b"XSDT" {
        return TestResult::Fail;
    }
    if SIG_SRAT != *b"SRAT" {
        return TestResult::Fail;
    }
    if SIG_SLIT != *b"SLIT" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rsdp_signature() -> TestResult {
    if RSDP_SIGNATURE != *b"RSD PTR " {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rsdp_alignment() -> TestResult {
    if RSDP_ALIGNMENT != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pm_profile_variants() -> TestResult {
    if PmProfile::Unspecified as u8 != 0 {
        return TestResult::Fail;
    }
    if PmProfile::Desktop as u8 != 1 {
        return TestResult::Fail;
    }
    if PmProfile::Mobile as u8 != 2 {
        return TestResult::Fail;
    }
    if PmProfile::Workstation as u8 != 3 {
        return TestResult::Fail;
    }
    if PmProfile::EnterpriseServer as u8 != 4 {
        return TestResult::Fail;
    }
    if PmProfile::SohoServer as u8 != 5 {
        return TestResult::Fail;
    }
    if PmProfile::AppliancePc as u8 != 6 {
        return TestResult::Fail;
    }
    if PmProfile::PerformanceServer as u8 != 7 {
        return TestResult::Fail;
    }
    if PmProfile::Tablet as u8 != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_madt_entry_types() -> TestResult {
    if MadtEntryType::LocalApic as u8 != 0 {
        return TestResult::Fail;
    }
    if MadtEntryType::IoApic as u8 != 1 {
        return TestResult::Fail;
    }
    if MadtEntryType::InterruptOverride as u8 != 2 {
        return TestResult::Fail;
    }
    if MadtEntryType::NmiSource as u8 != 3 {
        return TestResult::Fail;
    }
    if MadtEntryType::LocalApicNmi as u8 != 4 {
        return TestResult::Fail;
    }
    if MadtEntryType::LocalApicOverride as u8 != 5 {
        return TestResult::Fail;
    }
    if MadtEntryType::LocalX2Apic as u8 != 9 {
        return TestResult::Fail;
    }
    if MadtEntryType::LocalX2ApicNmi as u8 != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_srat_entry_types() -> TestResult {
    if SratEntryType::ProcessorAffinity as u8 != 0 {
        return TestResult::Fail;
    }
    if SratEntryType::MemoryAffinity as u8 != 1 {
        return TestResult::Fail;
    }
    if SratEntryType::X2ApicAffinity as u8 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_space_variants() -> TestResult {
    if AddressSpace::SystemMemory as u8 != 0 {
        return TestResult::Fail;
    }
    if AddressSpace::SystemIo as u8 != 1 {
        return TestResult::Fail;
    }
    if AddressSpace::PciConfig as u8 != 2 {
        return TestResult::Fail;
    }
    if AddressSpace::EmbeddedController as u8 != 3 {
        return TestResult::Fail;
    }
    if AddressSpace::SmBus as u8 != 4 {
        return TestResult::Fail;
    }
    if AddressSpace::Cmos as u8 != 5 {
        return TestResult::Fail;
    }
    if AddressSpace::PciBar as u8 != 6 {
        return TestResult::Fail;
    }
    if AddressSpace::Ipmi as u8 != 7 {
        return TestResult::Fail;
    }
    if AddressSpace::GeneralIo as u8 != 8 {
        return TestResult::Fail;
    }
    if AddressSpace::FunctionalFixed as u8 != 0x7F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_signatures_are_4_bytes() -> TestResult {
    if SIG_FADT.len() != 4 {
        return TestResult::Fail;
    }
    if SIG_HPET.len() != 4 {
        return TestResult::Fail;
    }
    if SIG_MADT.len() != 4 {
        return TestResult::Fail;
    }
    if SIG_MCFG.len() != 4 {
        return TestResult::Fail;
    }
    if SIG_RSDT.len() != 4 {
        return TestResult::Fail;
    }
    if SIG_XSDT.len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rsdp_signature_is_8_bytes() -> TestResult {
    if RSDP_SIGNATURE.len() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rsdp_alignment_power_of_two() -> TestResult {
    if !RSDP_ALIGNMENT.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
