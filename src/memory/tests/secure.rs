use crate::memory::secure_memory::{
    RegionType, SecurityLevel, MemoryRegion, ManagerStats, SecureMemoryError,
    MIN_ALLOCATION_SIZE, MAX_ALLOCATION_SIZE, DEFAULT_ALIGNMENT, PAGE_SIZE,
    SECURE_SCRUB_PATTERN, SECURE_SCRUB_PASSES, MAX_ALLOCATION_COUNT, MAX_MEMORY_USAGE,
    KERNEL_PROCESS_ID, INVALID_PROCESS_ID, PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_USER,
    SECURITY_LEVEL_PUBLIC, SECURITY_LEVEL_INTERNAL, SECURITY_LEVEL_CONFIDENTIAL,
    SECURITY_LEVEL_SECRET, SECURITY_LEVEL_TOP_SECRET, ENCRYPTION_THRESHOLD_LEVEL,
    REGION_TYPE_CODE, REGION_TYPE_DATA, REGION_TYPE_STACK, REGION_TYPE_HEAP,
    REGION_TYPE_DEVICE, REGION_TYPE_CAPSULE,
    INITIAL_REGION_ID, MAX_REGIONS, INVALID_REGION_ID,
};
use x86_64::{PhysAddr, VirtAddr};

#[test]
fn test_region_type_code() {
    let rt = RegionType::Code;
    assert_eq!(rt.as_u8(), REGION_TYPE_CODE);
    assert_eq!(rt.as_str(), "Code");
    assert!(!rt.is_writable());
    assert!(rt.is_executable());
}

#[test]
fn test_region_type_data() {
    let rt = RegionType::Data;
    assert_eq!(rt.as_u8(), REGION_TYPE_DATA);
    assert_eq!(rt.as_str(), "Data");
    assert!(rt.is_writable());
    assert!(!rt.is_executable());
}

#[test]
fn test_region_type_stack() {
    let rt = RegionType::Stack;
    assert_eq!(rt.as_u8(), REGION_TYPE_STACK);
    assert_eq!(rt.as_str(), "Stack");
    assert!(rt.is_writable());
    assert!(!rt.is_executable());
}

#[test]
fn test_region_type_heap() {
    let rt = RegionType::Heap;
    assert_eq!(rt.as_u8(), REGION_TYPE_HEAP);
    assert_eq!(rt.as_str(), "Heap");
    assert!(rt.is_writable());
    assert!(!rt.is_executable());
}

#[test]
fn test_region_type_device() {
    let rt = RegionType::Device;
    assert_eq!(rt.as_u8(), REGION_TYPE_DEVICE);
    assert_eq!(rt.as_str(), "Device");
    assert!(rt.is_writable());
    assert!(!rt.is_executable());
}

#[test]
fn test_region_type_capsule() {
    let rt = RegionType::Capsule;
    assert_eq!(rt.as_u8(), REGION_TYPE_CAPSULE);
    assert_eq!(rt.as_str(), "Capsule");
    assert!(!rt.is_writable());
    assert!(!rt.is_executable());
}

#[test]
fn test_region_type_equality() {
    assert_eq!(RegionType::Code, RegionType::Code);
    assert_ne!(RegionType::Code, RegionType::Data);
}

#[test]
fn test_region_type_clone() {
    let rt = RegionType::Stack;
    let cloned = rt.clone();
    assert_eq!(rt, cloned);
}

#[test]
fn test_security_level_public() {
    let sl = SecurityLevel::Public;
    assert_eq!(sl.as_u8(), SECURITY_LEVEL_PUBLIC);
    assert_eq!(sl.as_str(), "Public");
    assert!(!sl.requires_encryption());
    assert!(!sl.requires_secure_scrub());
    assert_eq!(sl.scrub_passes(), 0);
}

#[test]
fn test_security_level_internal() {
    let sl = SecurityLevel::Internal;
    assert_eq!(sl.as_u8(), SECURITY_LEVEL_INTERNAL);
    assert_eq!(sl.as_str(), "Internal");
    assert!(!sl.requires_encryption());
    assert!(!sl.requires_secure_scrub());
    assert_eq!(sl.scrub_passes(), 0);
}

#[test]
fn test_security_level_confidential() {
    let sl = SecurityLevel::Confidential;
    assert_eq!(sl.as_u8(), SECURITY_LEVEL_CONFIDENTIAL);
    assert_eq!(sl.as_str(), "Confidential");
    assert!(!sl.requires_encryption());
    assert!(!sl.requires_secure_scrub());
    assert_eq!(sl.scrub_passes(), 0);
}

#[test]
fn test_security_level_secret() {
    let sl = SecurityLevel::Secret;
    assert_eq!(sl.as_u8(), SECURITY_LEVEL_SECRET);
    assert_eq!(sl.as_str(), "Secret");
    assert!(sl.requires_encryption());
    assert!(sl.requires_secure_scrub());
    assert_eq!(sl.scrub_passes(), 1);
}

#[test]
fn test_security_level_top_secret() {
    let sl = SecurityLevel::TopSecret;
    assert_eq!(sl.as_u8(), SECURITY_LEVEL_TOP_SECRET);
    assert_eq!(sl.as_str(), "TopSecret");
    assert!(sl.requires_encryption());
    assert!(sl.requires_secure_scrub());
    assert_eq!(sl.scrub_passes(), SECURE_SCRUB_PASSES);
}

#[test]
fn test_security_level_ordering() {
    assert!(SecurityLevel::Public < SecurityLevel::Internal);
    assert!(SecurityLevel::Internal < SecurityLevel::Confidential);
    assert!(SecurityLevel::Confidential < SecurityLevel::Secret);
    assert!(SecurityLevel::Secret < SecurityLevel::TopSecret);
}

#[test]
fn test_security_level_equality() {
    assert_eq!(SecurityLevel::Secret, SecurityLevel::Secret);
    assert_ne!(SecurityLevel::Secret, SecurityLevel::TopSecret);
}

#[test]
fn test_security_level_clone() {
    let sl = SecurityLevel::Confidential;
    let cloned = sl.clone();
    assert_eq!(sl, cloned);
}

#[test]
fn test_memory_region_new() {
    let va = VirtAddr::new(0x1000);
    let pa = PhysAddr::new(0x2000);
    let region = MemoryRegion::new(
        1, va, pa, 4096, RegionType::Data, SecurityLevel::Internal, 42, 1000
    );
    assert_eq!(region.region_id, 1);
    assert_eq!(region.virtual_addr, va);
    assert_eq!(region.physical_addr, pa);
    assert_eq!(region.size, 4096);
    assert_eq!(region.region_type, RegionType::Data);
    assert_eq!(region.security_level, SecurityLevel::Internal);
    assert_eq!(region.owner_process, 42);
    assert!(!region.encrypted);
    assert_eq!(region.creation_time, 1000);
    assert_eq!(region.access_count, 0);
}

#[test]
fn test_memory_region_encrypted_secret() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        4096, RegionType::Data, SecurityLevel::Secret, 42, 1000
    );
    assert!(region.encrypted);
}

#[test]
fn test_memory_region_encrypted_top_secret() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        4096, RegionType::Data, SecurityLevel::TopSecret, 42, 1000
    );
    assert!(region.encrypted);
}

#[test]
fn test_memory_region_not_encrypted_public() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        4096, RegionType::Data, SecurityLevel::Public, 42, 1000
    );
    assert!(!region.encrypted);
}

#[test]
fn test_memory_region_end_addr() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        4096, RegionType::Data, SecurityLevel::Public, 42, 1000
    );
    assert_eq!(region.end_addr(), VirtAddr::new(0x2000));
}

#[test]
fn test_memory_region_contains_inside() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        4096, RegionType::Data, SecurityLevel::Public, 42, 1000
    );
    assert!(region.contains(VirtAddr::new(0x1000)));
    assert!(region.contains(VirtAddr::new(0x1FFF)));
}

#[test]
fn test_memory_region_contains_outside() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        4096, RegionType::Data, SecurityLevel::Public, 42, 1000
    );
    assert!(!region.contains(VirtAddr::new(0x0FFF)));
    assert!(!region.contains(VirtAddr::new(0x2000)));
}

#[test]
fn test_memory_region_page_count_single() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        4096, RegionType::Data, SecurityLevel::Public, 42, 1000
    );
    assert_eq!(region.page_count(), 1);
}

#[test]
fn test_memory_region_page_count_multiple() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        8192, RegionType::Data, SecurityLevel::Public, 42, 1000
    );
    assert_eq!(region.page_count(), 2);
}

#[test]
fn test_memory_region_page_count_partial() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        4097, RegionType::Data, SecurityLevel::Public, 42, 1000
    );
    assert_eq!(region.page_count(), 2);
}

#[test]
fn test_memory_region_clone() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        4096, RegionType::Data, SecurityLevel::Internal, 42, 1000
    );
    let cloned = region.clone();
    assert_eq!(region.region_id, cloned.region_id);
    assert_eq!(region.virtual_addr, cloned.virtual_addr);
    assert_eq!(region.size, cloned.size);
}

#[test]
fn test_manager_stats_utilization_percent() {
    let stats = ManagerStats {
        total_regions: 10,
        allocated_memory: 50,
        peak_memory: 100,
        allocations: 20,
        deallocations: 10,
    };
    assert!((stats.utilization_percent() - 50.0).abs() < 0.001);
}

#[test]
fn test_manager_stats_utilization_percent_zero_peak() {
    let stats = ManagerStats {
        total_regions: 0,
        allocated_memory: 0,
        peak_memory: 0,
        allocations: 0,
        deallocations: 0,
    };
    assert_eq!(stats.utilization_percent(), 0.0);
}

#[test]
fn test_manager_stats_clone() {
    let stats = ManagerStats {
        total_regions: 5,
        allocated_memory: 1000,
        peak_memory: 2000,
        allocations: 10,
        deallocations: 5,
    };
    let cloned = stats.clone();
    assert_eq!(stats.total_regions, cloned.total_regions);
    assert_eq!(stats.allocated_memory, cloned.allocated_memory);
}

#[test]
fn test_secure_memory_error_variants() {
    assert_eq!(SecureMemoryError::NotInitialized, SecureMemoryError::NotInitialized);
    assert_eq!(SecureMemoryError::AlreadyInitialized, SecureMemoryError::AlreadyInitialized);
    assert_eq!(SecureMemoryError::InvalidSize, SecureMemoryError::InvalidSize);
    assert_eq!(SecureMemoryError::AllocationFailed, SecureMemoryError::AllocationFailed);
    assert_eq!(SecureMemoryError::AddressNotFound, SecureMemoryError::AddressNotFound);
    assert_eq!(SecureMemoryError::RegionNotFound, SecureMemoryError::RegionNotFound);
    assert_eq!(SecureMemoryError::TranslationFailed, SecureMemoryError::TranslationFailed);
    assert_eq!(SecureMemoryError::ZeroingFailed, SecureMemoryError::ZeroingFailed);
    assert_eq!(SecureMemoryError::AccessDenied, SecureMemoryError::AccessDenied);
    assert_eq!(SecureMemoryError::InvalidSecurityLevel, SecureMemoryError::InvalidSecurityLevel);
    assert_eq!(SecureMemoryError::InvalidRegionType, SecureMemoryError::InvalidRegionType);
    assert_eq!(SecureMemoryError::RegionLimitExceeded, SecureMemoryError::RegionLimitExceeded);
    assert_eq!(SecureMemoryError::OwnershipViolation, SecureMemoryError::OwnershipViolation);
    assert_eq!(SecureMemoryError::WriteToReadOnly, SecureMemoryError::WriteToReadOnly);
    assert_eq!(SecureMemoryError::ExecuteViolation, SecureMemoryError::ExecuteViolation);
    assert_eq!(SecureMemoryError::AlreadyDeallocated, SecureMemoryError::AlreadyDeallocated);
    assert_eq!(SecureMemoryError::InvalidAddress, SecureMemoryError::InvalidAddress);
    assert_eq!(SecureMemoryError::SystemRegionProtected, SecureMemoryError::SystemRegionProtected);
    assert_eq!(SecureMemoryError::InternalCorruption, SecureMemoryError::InternalCorruption);
}

#[test]
fn test_secure_memory_error_clone() {
    let err = SecureMemoryError::AccessDenied;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_limits_constants() {
    assert_eq!(MIN_ALLOCATION_SIZE, 1);
    assert_eq!(MAX_ALLOCATION_SIZE, 1024 * 1024 * 1024);
    assert_eq!(DEFAULT_ALIGNMENT, 16);
    assert_eq!(PAGE_SIZE, 4096);
}

#[test]
fn test_scrub_constants() {
    assert_eq!(SECURE_SCRUB_PATTERN, 0xAA);
    assert_eq!(SECURE_SCRUB_PASSES, 3);
}

#[test]
fn test_max_constants() {
    assert_eq!(MAX_ALLOCATION_COUNT, u64::MAX - 1);
    assert_eq!(MAX_MEMORY_USAGE, u64::MAX - 1);
}

#[test]
fn test_process_id_constants() {
    assert_eq!(KERNEL_PROCESS_ID, 0);
    assert_eq!(INVALID_PROCESS_ID, u64::MAX);
}

#[test]
fn test_permission_constants() {
    assert_eq!(PERM_READ, 0x01);
    assert_eq!(PERM_WRITE, 0x02);
    assert_eq!(PERM_EXECUTE, 0x04);
    assert_eq!(PERM_USER, 0x08);
}

#[test]
fn test_security_level_constants() {
    assert_eq!(SECURITY_LEVEL_PUBLIC, 0);
    assert_eq!(SECURITY_LEVEL_INTERNAL, 1);
    assert_eq!(SECURITY_LEVEL_CONFIDENTIAL, 2);
    assert_eq!(SECURITY_LEVEL_SECRET, 3);
    assert_eq!(SECURITY_LEVEL_TOP_SECRET, 4);
}

#[test]
fn test_encryption_threshold() {
    assert_eq!(ENCRYPTION_THRESHOLD_LEVEL, SECURITY_LEVEL_SECRET);
}

#[test]
fn test_region_type_constants() {
    assert_eq!(REGION_TYPE_CODE, 0);
    assert_eq!(REGION_TYPE_DATA, 1);
    assert_eq!(REGION_TYPE_STACK, 2);
    assert_eq!(REGION_TYPE_HEAP, 3);
    assert_eq!(REGION_TYPE_DEVICE, 4);
    assert_eq!(REGION_TYPE_CAPSULE, 5);
}

#[test]
fn test_region_id_constants() {
    assert_eq!(INITIAL_REGION_ID, 1);
    assert_eq!(MAX_REGIONS, 65536);
    assert_eq!(INVALID_REGION_ID, 0);
}

#[test]
fn test_security_level_all_variants() {
    let levels = [
        SecurityLevel::Public,
        SecurityLevel::Internal,
        SecurityLevel::Confidential,
        SecurityLevel::Secret,
        SecurityLevel::TopSecret,
    ];
    for i in 0..levels.len() {
        for j in (i+1)..levels.len() {
            assert!(levels[i] < levels[j]);
        }
    }
}

#[test]
fn test_region_type_same_value() {
    let rt1 = RegionType::Code;
    let rt2 = RegionType::Code;
    assert_eq!(rt1, rt2);
}

#[test]
fn test_security_level_same_value() {
    let sl1 = SecurityLevel::Secret;
    let sl2 = SecurityLevel::Secret;
    assert_eq!(sl1, sl2);
}

#[test]
fn test_memory_region_large_size() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        1024 * 1024 * 1024, RegionType::Heap, SecurityLevel::Public, 42, 1000
    );
    assert_eq!(region.page_count(), 262144);
}

#[test]
fn test_region_type_all_writable() {
    assert!(RegionType::Data.is_writable());
    assert!(RegionType::Stack.is_writable());
    assert!(RegionType::Heap.is_writable());
    assert!(RegionType::Device.is_writable());
}

#[test]
fn test_region_type_all_not_writable() {
    assert!(!RegionType::Code.is_writable());
    assert!(!RegionType::Capsule.is_writable());
}

#[test]
fn test_region_type_all_executable() {
    assert!(RegionType::Code.is_executable());
}

#[test]
fn test_region_type_all_not_executable() {
    assert!(!RegionType::Data.is_executable());
    assert!(!RegionType::Stack.is_executable());
    assert!(!RegionType::Heap.is_executable());
    assert!(!RegionType::Device.is_executable());
    assert!(!RegionType::Capsule.is_executable());
}

#[test]
fn test_manager_stats_fields() {
    let stats = ManagerStats {
        total_regions: 100,
        allocated_memory: 1024 * 1024,
        peak_memory: 2 * 1024 * 1024,
        allocations: 150,
        deallocations: 50,
    };
    assert_eq!(stats.total_regions, 100);
    assert_eq!(stats.allocated_memory, 1024 * 1024);
    assert_eq!(stats.peak_memory, 2 * 1024 * 1024);
    assert_eq!(stats.allocations, 150);
    assert_eq!(stats.deallocations, 50);
}

#[test]
fn test_memory_region_boundary_address() {
    let region = MemoryRegion::new(
        1, VirtAddr::new(0xFFFF_FFFF_FFFF_F000), PhysAddr::new(0x1000),
        4096, RegionType::Data, SecurityLevel::Public, 0, 0
    );
    assert_eq!(region.end_addr(), VirtAddr::new(0xFFFF_FFFF_FFFF_F000u64.wrapping_add(4096)));
}

#[test]
fn test_security_level_copy() {
    let sl1 = SecurityLevel::Confidential;
    let sl2 = sl1;
    assert_eq!(sl1, sl2);
}

#[test]
fn test_region_type_copy() {
    let rt1 = RegionType::Heap;
    let rt2 = rt1;
    assert_eq!(rt1, rt2);
}
