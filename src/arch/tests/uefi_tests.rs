// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::arch::x86_64::uefi::{Crc32, MemoryType, ResetType, VariableAttributes};
use crate::test::framework::TestResult;

pub(crate) fn test_reset_type_variants() -> TestResult {
    if ResetType::Cold as u32 != 0 {
        return TestResult::Fail;
    }
    if ResetType::Warm as u32 != 1 {
        return TestResult::Fail;
    }
    if ResetType::Shutdown as u32 != 2 {
        return TestResult::Fail;
    }
    if ResetType::PlatformSpecific as u32 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_conventional() -> TestResult {
    if MemoryType::Conventional as u32 != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_loader_code() -> TestResult {
    if MemoryType::LoaderCode as u32 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_loader_data() -> TestResult {
    if MemoryType::LoaderData as u32 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_boot_services_code() -> TestResult {
    if MemoryType::BootServicesCode as u32 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_boot_services_data() -> TestResult {
    if MemoryType::BootServicesData as u32 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_runtime_services_code() -> TestResult {
    if MemoryType::RuntimeServicesCode as u32 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_runtime_services_data() -> TestResult {
    if MemoryType::RuntimeServicesData as u32 != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_acpi_reclaim() -> TestResult {
    if MemoryType::AcpiReclaim as u32 != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_acpi_nvs() -> TestResult {
    if MemoryType::AcpiNvs as u32 != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_variable_attributes_nv() -> TestResult {
    let attrs = VariableAttributes::NON_VOLATILE;
    if !attrs.contains(VariableAttributes::NON_VOLATILE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_variable_attributes_bs() -> TestResult {
    let attrs = VariableAttributes::BOOTSERVICE_ACCESS;
    if !attrs.contains(VariableAttributes::BOOTSERVICE_ACCESS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_variable_attributes_rt() -> TestResult {
    let attrs = VariableAttributes::RUNTIME_ACCESS;
    if !attrs.contains(VariableAttributes::RUNTIME_ACCESS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_variable_attributes_combined() -> TestResult {
    let attrs = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS;
    if !attrs.contains(VariableAttributes::NON_VOLATILE) {
        return TestResult::Fail;
    }
    if !attrs.contains(VariableAttributes::BOOTSERVICE_ACCESS) {
        return TestResult::Fail;
    }
    if !attrs.contains(VariableAttributes::RUNTIME_ACCESS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crc32_new() -> TestResult {
    let crc = Crc32::new();
    if crc.value() != 0xFFFFFFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crc32_finalize_empty() -> TestResult {
    let crc = Crc32::new();
    let result = crc.finalize();
    if result != 0x00000000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crc32_update() -> TestResult {
    let mut crc = Crc32::new();
    crc.update(&[0x00]);
    let result = crc.finalize();
    if result == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
