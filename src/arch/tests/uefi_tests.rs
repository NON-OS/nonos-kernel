// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for arch/x86_64/uefi

use crate::arch::x86_64::uefi::{ResetType, MemoryType, VariableAttributes, Crc32};

#[test_case]
fn test_reset_type_variants() {
    assert_eq!(ResetType::Cold as u32, 0);
    assert_eq!(ResetType::Warm as u32, 1);
    assert_eq!(ResetType::Shutdown as u32, 2);
    assert_eq!(ResetType::PlatformSpecific as u32, 3);
}

#[test_case]
fn test_memory_type_conventional() {
    assert_eq!(MemoryType::Conventional as u32, 7);
}

#[test_case]
fn test_memory_type_loader_code() {
    assert_eq!(MemoryType::LoaderCode as u32, 1);
}

#[test_case]
fn test_memory_type_loader_data() {
    assert_eq!(MemoryType::LoaderData as u32, 2);
}

#[test_case]
fn test_memory_type_boot_services_code() {
    assert_eq!(MemoryType::BootServicesCode as u32, 3);
}

#[test_case]
fn test_memory_type_boot_services_data() {
    assert_eq!(MemoryType::BootServicesData as u32, 4);
}

#[test_case]
fn test_memory_type_runtime_services_code() {
    assert_eq!(MemoryType::RuntimeServicesCode as u32, 5);
}

#[test_case]
fn test_memory_type_runtime_services_data() {
    assert_eq!(MemoryType::RuntimeServicesData as u32, 6);
}

#[test_case]
fn test_memory_type_acpi_reclaim() {
    assert_eq!(MemoryType::AcpiReclaim as u32, 9);
}

#[test_case]
fn test_memory_type_acpi_nvs() {
    assert_eq!(MemoryType::AcpiNvs as u32, 10);
}

#[test_case]
fn test_variable_attributes_nv() {
    let attrs = VariableAttributes::NON_VOLATILE;
    assert!(attrs.contains(VariableAttributes::NON_VOLATILE));
}

#[test_case]
fn test_variable_attributes_bs() {
    let attrs = VariableAttributes::BOOTSERVICE_ACCESS;
    assert!(attrs.contains(VariableAttributes::BOOTSERVICE_ACCESS));
}

#[test_case]
fn test_variable_attributes_rt() {
    let attrs = VariableAttributes::RUNTIME_ACCESS;
    assert!(attrs.contains(VariableAttributes::RUNTIME_ACCESS));
}

#[test_case]
fn test_variable_attributes_combined() {
    let attrs = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS;
    assert!(attrs.contains(VariableAttributes::NON_VOLATILE));
    assert!(attrs.contains(VariableAttributes::BOOTSERVICE_ACCESS));
    assert!(attrs.contains(VariableAttributes::RUNTIME_ACCESS));
}

#[test_case]
fn test_crc32_new() {
    let crc = Crc32::new();
    assert_eq!(crc.value(), 0xFFFFFFFF);
}

#[test_case]
fn test_crc32_finalize_empty() {
    let crc = Crc32::new();
    let result = crc.finalize();
    assert_eq!(result, 0x00000000);
}

#[test_case]
fn test_crc32_update() {
    let mut crc = Crc32::new();
    crc.update(&[0x00]);
    let result = crc.finalize();
    assert_ne!(result, 0);
}
