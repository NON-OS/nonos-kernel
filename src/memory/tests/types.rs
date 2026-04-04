// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::memory::unified::{MemoryProtection, MemoryType};
use crate::memory::layout::{
    RegionKind, LayoutError,
    PAGE_SIZE, PAGE_SIZE_U64, PAGE_MASK, HUGE_PAGE_2M, HUGE_PAGE_1G,
    DIRECTMAP_BASE, DIRECTMAP_SIZE, KHEAP_BASE, KHEAP_SIZE, KVM_BASE, KVM_SIZE,
    MAX_PHYS_ADDR, MAX_CPUS,
};

#[test]
fn test_memory_protection_none() {
    let prot = MemoryProtection::None;
    assert_eq!(prot, MemoryProtection::None);
}

#[test]
fn test_memory_protection_read() {
    let prot = MemoryProtection::Read;
    assert_eq!(prot, MemoryProtection::Read);
}

#[test]
fn test_memory_protection_read_write() {
    let prot = MemoryProtection::ReadWrite;
    assert_eq!(prot, MemoryProtection::ReadWrite);
}

#[test]
fn test_memory_protection_read_execute() {
    let prot = MemoryProtection::ReadExecute;
    assert_eq!(prot, MemoryProtection::ReadExecute);
}

#[test]
fn test_memory_protection_equality() {
    assert_eq!(MemoryProtection::None, MemoryProtection::None);
    assert_eq!(MemoryProtection::Read, MemoryProtection::Read);
    assert_ne!(MemoryProtection::Read, MemoryProtection::ReadWrite);
    assert_ne!(MemoryProtection::ReadWrite, MemoryProtection::ReadExecute);
}

#[test]
fn test_memory_protection_clone() {
    let prot = MemoryProtection::ReadWrite;
    let cloned = prot.clone();
    assert_eq!(prot, cloned);
}

#[test]
fn test_memory_protection_copy() {
    let prot1 = MemoryProtection::Read;
    let prot2 = prot1;
    assert_eq!(prot1, prot2);
}

#[test]
fn test_memory_type_anonymous() {
    let mt = MemoryType::Anonymous;
    assert_eq!(mt, MemoryType::Anonymous);
}

#[test]
fn test_memory_type_kernel_code() {
    let mt = MemoryType::KernelCode;
    assert_eq!(mt, MemoryType::KernelCode);
}

#[test]
fn test_memory_type_kernel_data() {
    let mt = MemoryType::KernelData;
    assert_eq!(mt, MemoryType::KernelData);
}

#[test]
fn test_memory_type_user_code() {
    let mt = MemoryType::UserCode;
    assert_eq!(mt, MemoryType::UserCode);
}

#[test]
fn test_memory_type_user_data() {
    let mt = MemoryType::UserData;
    assert_eq!(mt, MemoryType::UserData);
}

#[test]
fn test_memory_type_user_heap() {
    let mt = MemoryType::UserHeap;
    assert_eq!(mt, MemoryType::UserHeap);
}

#[test]
fn test_memory_type_user_stack() {
    let mt = MemoryType::UserStack;
    assert_eq!(mt, MemoryType::UserStack);
}

#[test]
fn test_memory_type_device() {
    let mt = MemoryType::Device;
    assert_eq!(mt, MemoryType::Device);
}

#[test]
fn test_memory_type_secure_capsule() {
    let mt = MemoryType::SecureCapsule;
    assert_eq!(mt, MemoryType::SecureCapsule);
}

#[test]
fn test_memory_type_shared() {
    let mt = MemoryType::Shared;
    assert_eq!(mt, MemoryType::Shared);
}

#[test]
fn test_memory_type_equality() {
    assert_eq!(MemoryType::Anonymous, MemoryType::Anonymous);
    assert_eq!(MemoryType::KernelCode, MemoryType::KernelCode);
    assert_ne!(MemoryType::KernelCode, MemoryType::KernelData);
    assert_ne!(MemoryType::UserCode, MemoryType::UserData);
}

#[test]
fn test_memory_type_clone() {
    let mt = MemoryType::SecureCapsule;
    let cloned = mt.clone();
    assert_eq!(mt, cloned);
}

#[test]
fn test_memory_type_copy() {
    let mt1 = MemoryType::Device;
    let mt2 = mt1;
    assert_eq!(mt1, mt2);
}

#[test]
fn test_region_kind_available() {
    let rk = RegionKind::Available;
    assert_eq!(rk.as_str(), "Available");
    assert!(rk.is_usable());
}

#[test]
fn test_region_kind_usable() {
    let rk = RegionKind::Usable;
    assert_eq!(rk.as_str(), "Usable");
    assert!(rk.is_usable());
}

#[test]
fn test_region_kind_reserved() {
    let rk = RegionKind::Reserved;
    assert_eq!(rk.as_str(), "Reserved");
    assert!(!rk.is_usable());
}

#[test]
fn test_region_kind_acpi() {
    let rk = RegionKind::Acpi;
    assert_eq!(rk.as_str(), "ACPI");
    assert!(!rk.is_usable());
}

#[test]
fn test_region_kind_mmio() {
    let rk = RegionKind::Mmio;
    assert_eq!(rk.as_str(), "MMIO");
    assert!(!rk.is_usable());
}

#[test]
fn test_region_kind_kernel() {
    let rk = RegionKind::Kernel;
    assert_eq!(rk.as_str(), "Kernel");
    assert!(!rk.is_usable());
}

#[test]
fn test_region_kind_boot() {
    let rk = RegionKind::Boot;
    assert_eq!(rk.as_str(), "Boot");
    assert!(!rk.is_usable());
}

#[test]
fn test_region_kind_unknown() {
    let rk = RegionKind::Unknown;
    assert_eq!(rk.as_str(), "Unknown");
    assert!(!rk.is_usable());
}

#[test]
fn test_region_kind_equality() {
    assert_eq!(RegionKind::Available, RegionKind::Available);
    assert_ne!(RegionKind::Available, RegionKind::Reserved);
}

#[test]
fn test_region_kind_clone() {
    let rk = RegionKind::Kernel;
    let cloned = rk.clone();
    assert_eq!(rk, cloned);
}

#[test]
fn test_region_kind_copy() {
    let rk1 = RegionKind::Mmio;
    let rk2 = rk1;
    assert_eq!(rk1, rk2);
}

#[test]
fn test_layout_error_slide_not_aligned() {
    let err = LayoutError::SlideNotAligned;
    assert_eq!(err, LayoutError::SlideNotAligned);
}

#[test]
fn test_layout_error_kernel_base_too_low() {
    let err = LayoutError::KernelBaseTooLow;
    assert_eq!(err, LayoutError::KernelBaseTooLow);
}

#[test]
fn test_layout_error_percpu_stride_misaligned() {
    let err = LayoutError::PercpuStrideMisaligned;
    assert_eq!(err, LayoutError::PercpuStrideMisaligned);
}

#[test]
fn test_layout_error_window_overlap() {
    let err = LayoutError::WindowOverlap;
    assert_eq!(err, LayoutError::WindowOverlap);
}

#[test]
fn test_layout_error_order_violation() {
    let err = LayoutError::OrderViolation;
    assert_eq!(err, LayoutError::OrderViolation);
}

#[test]
fn test_layout_error_size_exceeds_capacity() {
    let err = LayoutError::SizeExceedsCapacity;
    assert_eq!(err, LayoutError::SizeExceedsCapacity);
}

#[test]
fn test_layout_error_not_in_kernel_space() {
    let err = LayoutError::NotInKernelSpace;
    assert_eq!(err, LayoutError::NotInKernelSpace);
}

#[test]
fn test_layout_error_not_in_user_space() {
    let err = LayoutError::NotInUserSpace;
    assert_eq!(err, LayoutError::NotInUserSpace);
}

#[test]
fn test_layout_error_invalid_alignment() {
    let err = LayoutError::InvalidAlignment;
    assert_eq!(err, LayoutError::InvalidAlignment);
}

#[test]
fn test_layout_error_not_initialized() {
    let err = LayoutError::NotInitialized;
    assert_eq!(err, LayoutError::NotInitialized);
}

#[test]
fn test_layout_error_config_locked() {
    let err = LayoutError::ConfigLocked;
    assert_eq!(err, LayoutError::ConfigLocked);
}

#[test]
fn test_layout_error_invalid_region_bounds() {
    let err = LayoutError::InvalidRegionBounds;
    assert_eq!(err, LayoutError::InvalidRegionBounds);
}

#[test]
fn test_layout_error_equality() {
    assert_eq!(LayoutError::SlideNotAligned, LayoutError::SlideNotAligned);
    assert_ne!(LayoutError::SlideNotAligned, LayoutError::WindowOverlap);
}

#[test]
fn test_layout_error_clone() {
    let err = LayoutError::OrderViolation;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_layout_error_copy() {
    let err1 = LayoutError::NotInitialized;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_page_size_constant() {
    assert_eq!(PAGE_SIZE, 4096);
    assert!(PAGE_SIZE.is_power_of_two());
}

#[test]
fn test_page_size_u64_constant() {
    assert_eq!(PAGE_SIZE_U64, 4096);
    assert_eq!(PAGE_SIZE_U64, PAGE_SIZE as u64);
}

#[test]
fn test_page_mask_constant() {
    assert_eq!(PAGE_MASK, !0xFFF);
    assert_eq!(0x12345678u64 & PAGE_MASK, 0x12345000u64);
}

#[test]
fn test_huge_page_2m_constant() {
    assert_eq!(HUGE_PAGE_2M, 2 * 1024 * 1024);
    assert!(HUGE_PAGE_2M.is_power_of_two());
}

#[test]
fn test_huge_page_1g_constant() {
    assert_eq!(HUGE_PAGE_1G, 1024 * 1024 * 1024);
    assert!(HUGE_PAGE_1G.is_power_of_two());
}

#[test]
fn test_directmap_base_constant() {
    assert_eq!(DIRECTMAP_BASE, 0xFFFF_FFFF_B000_0000);
}

#[test]
fn test_directmap_size_constant() {
    assert_eq!(DIRECTMAP_SIZE, 0x0000_0000_1000_0000);
}

#[test]
fn test_kheap_base_constant() {
    assert_eq!(KHEAP_BASE, 0xFFFF_FF00_0000_0000);
}

#[test]
fn test_kheap_size_constant() {
    assert_eq!(KHEAP_SIZE, 0x0000_0000_1000_0000);
}

#[test]
fn test_kvm_base_constant() {
    assert_eq!(KVM_BASE, 0xFFFF_FF10_0000_0000);
}

#[test]
fn test_kvm_size_constant() {
    assert_eq!(KVM_SIZE, 0x0000_0000_2000_0000);
}

#[test]
fn test_max_phys_addr_constant() {
    assert_eq!(MAX_PHYS_ADDR, 0x0000_FFFF_FFFF_FFFF);
}

#[test]
fn test_max_cpus_constant() {
    assert_eq!(MAX_CPUS, 64);
}

#[test]
fn test_page_alignment() {
    let aligned = 0x1000u64;
    let unaligned = 0x1001u64;
    assert_eq!(aligned & PAGE_MASK, aligned);
    assert_ne!(unaligned & PAGE_MASK, unaligned);
}

#[test]
fn test_page_offset() {
    let addr = 0x12345678u64;
    let offset = addr & !PAGE_MASK;
    assert_eq!(offset, 0x678);
}

#[test]
fn test_huge_page_sizes_ordering() {
    assert!(PAGE_SIZE < HUGE_PAGE_2M);
    assert!(HUGE_PAGE_2M < HUGE_PAGE_1G);
}

#[test]
fn test_region_sizes_valid() {
    assert!(DIRECTMAP_SIZE > 0);
    assert!(KHEAP_SIZE > 0);
    assert!(KVM_SIZE > 0);
}

#[test]
fn test_memory_type_all_variants() {
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
        assert_eq!(mt, cloned);
    }
}

#[test]
fn test_memory_protection_all_variants() {
    let prots = [
        MemoryProtection::None,
        MemoryProtection::Read,
        MemoryProtection::ReadWrite,
        MemoryProtection::ReadExecute,
    ];
    for prot in prots {
        let cloned = prot.clone();
        assert_eq!(prot, cloned);
    }
}

#[test]
fn test_region_kind_all_have_str() {
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
        assert!(!kind.as_str().is_empty());
    }
}

#[test]
fn test_layout_error_all_variants() {
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
        assert_eq!(err, cloned);
    }
}

