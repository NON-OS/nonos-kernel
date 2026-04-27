// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Memory type and layout tests

use crate::memory::layout::{
    LayoutError, RegionKind, DIRECTMAP_BASE, DIRECTMAP_SIZE, HUGE_PAGE_1G, HUGE_PAGE_2M,
    KHEAP_BASE, KHEAP_SIZE, KVM_BASE, KVM_SIZE, MAX_CPUS, MAX_PHYS_ADDR, PAGE_MASK, PAGE_SIZE,
    PAGE_SIZE_U64,
};
use crate::memory::unified::{MemoryProtection, MemoryType};
use crate::test::framework::TestResult;

pub(crate) fn test_memory_protection_none() -> TestResult {
    let prot = MemoryProtection::None;
    if prot != MemoryProtection::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_protection_read() -> TestResult {
    let prot = MemoryProtection::Read;
    if prot != MemoryProtection::Read {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_protection_read_write() -> TestResult {
    let prot = MemoryProtection::ReadWrite;
    if prot != MemoryProtection::ReadWrite {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_protection_read_execute() -> TestResult {
    let prot = MemoryProtection::ReadExecute;
    if prot != MemoryProtection::ReadExecute {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_protection_equality() -> TestResult {
    if MemoryProtection::None != MemoryProtection::None {
        return TestResult::Fail;
    }
    if MemoryProtection::Read != MemoryProtection::Read {
        return TestResult::Fail;
    }
    if MemoryProtection::Read == MemoryProtection::ReadWrite {
        return TestResult::Fail;
    }
    if MemoryProtection::ReadWrite == MemoryProtection::ReadExecute {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_protection_clone() -> TestResult {
    let prot = MemoryProtection::ReadWrite;
    let cloned = prot.clone();
    if prot != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_protection_copy() -> TestResult {
    let prot1 = MemoryProtection::Read;
    let prot2 = prot1;
    if prot1 != prot2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_anonymous() -> TestResult {
    let mt = MemoryType::Anonymous;
    if mt != MemoryType::Anonymous {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_kernel_code() -> TestResult {
    let mt = MemoryType::KernelCode;
    if mt != MemoryType::KernelCode {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_kernel_data() -> TestResult {
    let mt = MemoryType::KernelData;
    if mt != MemoryType::KernelData {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_user_code() -> TestResult {
    let mt = MemoryType::UserCode;
    if mt != MemoryType::UserCode {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_user_data() -> TestResult {
    let mt = MemoryType::UserData;
    if mt != MemoryType::UserData {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_user_heap() -> TestResult {
    let mt = MemoryType::UserHeap;
    if mt != MemoryType::UserHeap {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_user_stack() -> TestResult {
    let mt = MemoryType::UserStack;
    if mt != MemoryType::UserStack {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_device() -> TestResult {
    let mt = MemoryType::Device;
    if mt != MemoryType::Device {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_secure_capsule() -> TestResult {
    let mt = MemoryType::SecureCapsule;
    if mt != MemoryType::SecureCapsule {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_shared() -> TestResult {
    let mt = MemoryType::Shared;
    if mt != MemoryType::Shared {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_equality() -> TestResult {
    if MemoryType::Anonymous != MemoryType::Anonymous {
        return TestResult::Fail;
    }
    if MemoryType::KernelCode != MemoryType::KernelCode {
        return TestResult::Fail;
    }
    if MemoryType::KernelCode == MemoryType::KernelData {
        return TestResult::Fail;
    }
    if MemoryType::UserCode == MemoryType::UserData {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_clone() -> TestResult {
    let mt = MemoryType::SecureCapsule;
    let cloned = mt.clone();
    if mt != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_copy() -> TestResult {
    let mt1 = MemoryType::Device;
    let mt2 = mt1;
    if mt1 != mt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_available() -> TestResult {
    let rk = RegionKind::Available;
    if rk.as_str() != "Available" {
        return TestResult::Fail;
    }
    if !rk.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_usable() -> TestResult {
    let rk = RegionKind::Usable;
    if rk.as_str() != "Usable" {
        return TestResult::Fail;
    }
    if !rk.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_reserved() -> TestResult {
    let rk = RegionKind::Reserved;
    if rk.as_str() != "Reserved" {
        return TestResult::Fail;
    }
    if rk.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_acpi() -> TestResult {
    let rk = RegionKind::Acpi;
    if rk.as_str() != "ACPI" {
        return TestResult::Fail;
    }
    if rk.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_mmio() -> TestResult {
    let rk = RegionKind::Mmio;
    if rk.as_str() != "MMIO" {
        return TestResult::Fail;
    }
    if rk.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_kernel() -> TestResult {
    let rk = RegionKind::Kernel;
    if rk.as_str() != "Kernel" {
        return TestResult::Fail;
    }
    if rk.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_boot() -> TestResult {
    let rk = RegionKind::Boot;
    if rk.as_str() != "Boot" {
        return TestResult::Fail;
    }
    if rk.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_unknown() -> TestResult {
    let rk = RegionKind::Unknown;
    if rk.as_str() != "Unknown" {
        return TestResult::Fail;
    }
    if rk.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_equality() -> TestResult {
    if RegionKind::Available != RegionKind::Available {
        return TestResult::Fail;
    }
    if RegionKind::Available == RegionKind::Reserved {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_clone() -> TestResult {
    let rk = RegionKind::Kernel;
    let cloned = rk.clone();
    if rk != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_copy() -> TestResult {
    let rk1 = RegionKind::Mmio;
    let rk2 = rk1;
    if rk1 != rk2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_slide_not_aligned() -> TestResult {
    let err = LayoutError::SlideNotAligned;
    if err != LayoutError::SlideNotAligned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_kernel_base_too_low() -> TestResult {
    let err = LayoutError::KernelBaseTooLow;
    if err != LayoutError::KernelBaseTooLow {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_percpu_stride_misaligned() -> TestResult {
    let err = LayoutError::PercpuStrideMisaligned;
    if err != LayoutError::PercpuStrideMisaligned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_window_overlap() -> TestResult {
    let err = LayoutError::WindowOverlap;
    if err != LayoutError::WindowOverlap {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_order_violation() -> TestResult {
    let err = LayoutError::OrderViolation;
    if err != LayoutError::OrderViolation {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_size_exceeds_capacity() -> TestResult {
    let err = LayoutError::SizeExceedsCapacity;
    if err != LayoutError::SizeExceedsCapacity {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_not_in_kernel_space() -> TestResult {
    let err = LayoutError::NotInKernelSpace;
    if err != LayoutError::NotInKernelSpace {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_not_in_user_space() -> TestResult {
    let err = LayoutError::NotInUserSpace;
    if err != LayoutError::NotInUserSpace {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_invalid_alignment() -> TestResult {
    let err = LayoutError::InvalidAlignment;
    if err != LayoutError::InvalidAlignment {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_not_initialized() -> TestResult {
    let err = LayoutError::NotInitialized;
    if err != LayoutError::NotInitialized {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_config_locked() -> TestResult {
    let err = LayoutError::ConfigLocked;
    if err != LayoutError::ConfigLocked {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_invalid_region_bounds() -> TestResult {
    let err = LayoutError::InvalidRegionBounds;
    if err != LayoutError::InvalidRegionBounds {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_equality() -> TestResult {
    if LayoutError::SlideNotAligned != LayoutError::SlideNotAligned {
        return TestResult::Fail;
    }
    if LayoutError::SlideNotAligned == LayoutError::WindowOverlap {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_clone() -> TestResult {
    let err = LayoutError::OrderViolation;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_copy() -> TestResult {
    let err1 = LayoutError::NotInitialized;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_constant() -> TestResult {
    if PAGE_SIZE != 4096 {
        return TestResult::Fail;
    }
    if !PAGE_SIZE.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_u64_constant() -> TestResult {
    if PAGE_SIZE_U64 != 4096 {
        return TestResult::Fail;
    }
    if PAGE_SIZE_U64 != PAGE_SIZE as u64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mask_constant() -> TestResult {
    if PAGE_MASK != !0xFFF {
        return TestResult::Fail;
    }
    if 0x12345678u64 & PAGE_MASK != 0x12345000u64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_huge_page_2m_constant() -> TestResult {
    if HUGE_PAGE_2M != 2 * 1024 * 1024 {
        return TestResult::Fail;
    }
    if !HUGE_PAGE_2M.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_huge_page_1g_constant() -> TestResult {
    if HUGE_PAGE_1G != 1024 * 1024 * 1024 {
        return TestResult::Fail;
    }
    if !HUGE_PAGE_1G.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_directmap_base_constant() -> TestResult {
    if DIRECTMAP_BASE != 0xFFFF_FFFF_B000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_directmap_size_constant() -> TestResult {
    if DIRECTMAP_SIZE != 0x0000_0000_1000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kheap_base_constant() -> TestResult {
    if KHEAP_BASE != 0xFFFF_FF00_0000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kheap_size_constant() -> TestResult {
    if KHEAP_SIZE != 0x0000_0000_1000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kvm_base_constant() -> TestResult {
    if KVM_BASE != 0xFFFF_FF10_0000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kvm_size_constant() -> TestResult {
    if KVM_SIZE != 0x0000_0000_2000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_phys_addr_constant() -> TestResult {
    if MAX_PHYS_ADDR != 0x0000_FFFF_FFFF_FFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_cpus_constant() -> TestResult {
    if MAX_CPUS != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_alignment() -> TestResult {
    let aligned = 0x1000u64;
    let unaligned = 0x1001u64;
    if aligned & PAGE_MASK != aligned {
        return TestResult::Fail;
    }
    if unaligned & PAGE_MASK == unaligned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_offset() -> TestResult {
    let addr = 0x12345678u64;
    let offset = addr & !PAGE_MASK;
    if offset != 0x678 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_huge_page_sizes_ordering() -> TestResult {
    if PAGE_SIZE >= HUGE_PAGE_2M {
        return TestResult::Fail;
    }
    if HUGE_PAGE_2M >= HUGE_PAGE_1G {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_sizes_valid() -> TestResult {
    if DIRECTMAP_SIZE == 0 {
        return TestResult::Fail;
    }
    if KHEAP_SIZE == 0 {
        return TestResult::Fail;
    }
    if KVM_SIZE == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_type_all_variants() -> TestResult {
    let types = [
        MemoryType::Anonymous,
        MemoryType::KernelCode,
        MemoryType::KernelData,
        MemoryType::UserCode,
        MemoryType::UserData,
        MemoryType::UserHeap,
        MemoryType::UserStack,
        MemoryType::Device,
        MemoryType::SecureCapsule,
        MemoryType::Shared,
    ];
    for mt in types {
        let cloned = mt.clone();
        if mt != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_memory_protection_all_variants() -> TestResult {
    let prots = [
        MemoryProtection::None,
        MemoryProtection::Read,
        MemoryProtection::ReadWrite,
        MemoryProtection::ReadExecute,
    ];
    for prot in prots {
        let cloned = prot.clone();
        if prot != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_region_kind_all_have_str() -> TestResult {
    let kinds = [
        RegionKind::Available,
        RegionKind::Usable,
        RegionKind::Reserved,
        RegionKind::Acpi,
        RegionKind::Mmio,
        RegionKind::Kernel,
        RegionKind::Boot,
        RegionKind::Unknown,
    ];
    for kind in kinds {
        if kind.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_layout_error_all_variants() -> TestResult {
    let errors = [
        LayoutError::SlideNotAligned,
        LayoutError::KernelBaseTooLow,
        LayoutError::PercpuStrideMisaligned,
        LayoutError::WindowOverlap,
        LayoutError::OrderViolation,
        LayoutError::SizeExceedsCapacity,
        LayoutError::NotInKernelSpace,
        LayoutError::NotInUserSpace,
        LayoutError::InvalidAlignment,
        LayoutError::NotInitialized,
        LayoutError::ConfigLocked,
        LayoutError::InvalidRegionBounds,
    ];
    for err in errors {
        let cloned = err.clone();
        if err != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
