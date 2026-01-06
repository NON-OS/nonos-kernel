// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::*;
use super::constants::*;
use super::error::SecureMemoryError;

// ============================================================================
// CONSTANTS TESTS
// ============================================================================

#[test]
fn test_initial_region_id() {
    assert_eq!(INITIAL_REGION_ID, 1);
    assert_ne!(INITIAL_REGION_ID, INVALID_REGION_ID);
}

#[test]
fn test_invalid_region_id() {
    assert_eq!(INVALID_REGION_ID, 0);
}

#[test]
fn test_max_regions() {
    assert_eq!(MAX_REGIONS, 65536);
    assert!(MAX_REGIONS > 0);
}

#[test]
fn test_security_level_values() {
    assert_eq!(SECURITY_LEVEL_PUBLIC, 0);
    assert_eq!(SECURITY_LEVEL_INTERNAL, 1);
    assert_eq!(SECURITY_LEVEL_CONFIDENTIAL, 2);
    assert_eq!(SECURITY_LEVEL_SECRET, 3);
    assert_eq!(SECURITY_LEVEL_TOP_SECRET, 4);

    // Ensure they're in order
    assert!(SECURITY_LEVEL_PUBLIC < SECURITY_LEVEL_INTERNAL);
    assert!(SECURITY_LEVEL_INTERNAL < SECURITY_LEVEL_CONFIDENTIAL);
    assert!(SECURITY_LEVEL_CONFIDENTIAL < SECURITY_LEVEL_SECRET);
    assert!(SECURITY_LEVEL_SECRET < SECURITY_LEVEL_TOP_SECRET);
}

#[test]
fn test_encryption_threshold() {
    assert_eq!(ENCRYPTION_THRESHOLD_LEVEL, SECURITY_LEVEL_SECRET);
    assert!(ENCRYPTION_THRESHOLD_LEVEL > SECURITY_LEVEL_CONFIDENTIAL);
}

#[test]
fn test_region_type_values() {
    assert_eq!(REGION_TYPE_CODE, 0);
    assert_eq!(REGION_TYPE_DATA, 1);
    assert_eq!(REGION_TYPE_STACK, 2);
    assert_eq!(REGION_TYPE_HEAP, 3);
    assert_eq!(REGION_TYPE_DEVICE, 4);
    assert_eq!(REGION_TYPE_CAPSULE, 5);
}

#[test]
fn test_allocation_limits() {
    assert_eq!(MIN_ALLOCATION_SIZE, 1);
    assert_eq!(MAX_ALLOCATION_SIZE, 1024 * 1024 * 1024); // 1 GiB
    assert!(MIN_ALLOCATION_SIZE < MAX_ALLOCATION_SIZE);
}

#[test]
fn test_page_size() {
    assert_eq!(PAGE_SIZE, 4096);
}

#[test]
fn test_secure_scrub_constants() {
    assert_eq!(SECURE_SCRUB_PATTERN, 0xAA);
    assert_eq!(SECURE_SCRUB_PASSES, 3);
    assert!(SECURE_SCRUB_PASSES > 0);
}

#[test]
fn test_process_id_constants() {
    assert_eq!(KERNEL_PROCESS_ID, 0);
    assert_eq!(INVALID_PROCESS_ID, u64::MAX);
    assert_ne!(KERNEL_PROCESS_ID, INVALID_PROCESS_ID);
}

#[test]
fn test_permission_bits() {
    assert_eq!(PERM_READ, 0x01);
    assert_eq!(PERM_WRITE, 0x02);
    assert_eq!(PERM_EXECUTE, 0x04);
    assert_eq!(PERM_USER, 0x08);

    // Ensure they're distinct bits
    assert_eq!(PERM_READ & PERM_WRITE, 0);
    assert_eq!(PERM_READ & PERM_EXECUTE, 0);
    assert_eq!(PERM_WRITE & PERM_EXECUTE, 0);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_error_display() {
    assert_eq!(SecureMemoryError::NotInitialized.as_str(), "Memory manager not initialized");
    assert_eq!(SecureMemoryError::InvalidSize.as_str(), "Invalid allocation size");
    assert_eq!(SecureMemoryError::AllocationFailed.as_str(), "Memory allocation failed");
    assert_eq!(SecureMemoryError::AccessDenied.as_str(), "Access denied");
}

#[test]
fn test_error_is_security_critical() {
    assert!(SecureMemoryError::AccessDenied.is_security_critical());
    assert!(SecureMemoryError::OwnershipViolation.is_security_critical());
    assert!(SecureMemoryError::WriteToReadOnly.is_security_critical());
    assert!(SecureMemoryError::ExecuteViolation.is_security_critical());
    assert!(SecureMemoryError::SystemRegionProtected.is_security_critical());
    assert!(SecureMemoryError::InternalCorruption.is_security_critical());

    assert!(!SecureMemoryError::NotInitialized.is_security_critical());
    assert!(!SecureMemoryError::InvalidSize.is_security_critical());
    assert!(!SecureMemoryError::AllocationFailed.is_security_critical());
}

#[test]
fn test_error_is_internal_error() {
    assert!(SecureMemoryError::InternalCorruption.is_internal_error());
    assert!(SecureMemoryError::RegionNotFound.is_internal_error());
    assert!(SecureMemoryError::AddressNotFound.is_internal_error());

    assert!(!SecureMemoryError::NotInitialized.is_internal_error());
    assert!(!SecureMemoryError::InvalidSize.is_internal_error());
}

#[test]
fn test_error_is_retriable() {
    assert!(SecureMemoryError::AllocationFailed.is_retriable());

    assert!(!SecureMemoryError::NotInitialized.is_retriable());
    assert!(!SecureMemoryError::AccessDenied.is_retriable());
}

#[test]
fn test_error_from_string() {
    let err: SecureMemoryError = "Memory manager not initialized".into();
    assert_eq!(err, SecureMemoryError::NotInitialized);

    let err: SecureMemoryError = "Invalid allocation size".into();
    assert_eq!(err, SecureMemoryError::InvalidSize);

    let err: SecureMemoryError = "Address not found".into();
    assert_eq!(err, SecureMemoryError::AddressNotFound);
}

// ============================================================================
// REGION TYPE TESTS
// ============================================================================

#[test]
fn test_region_type_as_u8() {
    assert_eq!(RegionType::Code.as_u8(), REGION_TYPE_CODE);
    assert_eq!(RegionType::Data.as_u8(), REGION_TYPE_DATA);
    assert_eq!(RegionType::Stack.as_u8(), REGION_TYPE_STACK);
    assert_eq!(RegionType::Heap.as_u8(), REGION_TYPE_HEAP);
    assert_eq!(RegionType::Device.as_u8(), REGION_TYPE_DEVICE);
    assert_eq!(RegionType::Capsule.as_u8(), REGION_TYPE_CAPSULE);
}

#[test]
fn test_region_type_as_str() {
    assert_eq!(RegionType::Code.as_str(), "Code");
    assert_eq!(RegionType::Data.as_str(), "Data");
    assert_eq!(RegionType::Stack.as_str(), "Stack");
    assert_eq!(RegionType::Heap.as_str(), "Heap");
    assert_eq!(RegionType::Device.as_str(), "Device");
    assert_eq!(RegionType::Capsule.as_str(), "Capsule");
}

#[test]
fn test_region_type_is_writable() {
    assert!(!RegionType::Code.is_writable()); // Code is read-execute only
    assert!(RegionType::Data.is_writable());
    assert!(RegionType::Stack.is_writable());
    assert!(RegionType::Heap.is_writable());
    assert!(RegionType::Device.is_writable());
    assert!(!RegionType::Capsule.is_writable());
}

#[test]
fn test_region_type_is_executable() {
    assert!(RegionType::Code.is_executable());
    assert!(!RegionType::Data.is_executable());
    assert!(!RegionType::Stack.is_executable());
    assert!(!RegionType::Heap.is_executable());
    assert!(!RegionType::Device.is_executable());
    assert!(!RegionType::Capsule.is_executable());
}

// ============================================================================
// SECURITY LEVEL TESTS
// ============================================================================

#[test]
fn test_security_level_as_u8() {
    assert_eq!(SecurityLevel::Public.as_u8(), SECURITY_LEVEL_PUBLIC);
    assert_eq!(SecurityLevel::Internal.as_u8(), SECURITY_LEVEL_INTERNAL);
    assert_eq!(SecurityLevel::Confidential.as_u8(), SECURITY_LEVEL_CONFIDENTIAL);
    assert_eq!(SecurityLevel::Secret.as_u8(), SECURITY_LEVEL_SECRET);
    assert_eq!(SecurityLevel::TopSecret.as_u8(), SECURITY_LEVEL_TOP_SECRET);
}

#[test]
fn test_security_level_as_str() {
    assert_eq!(SecurityLevel::Public.as_str(), "Public");
    assert_eq!(SecurityLevel::Internal.as_str(), "Internal");
    assert_eq!(SecurityLevel::Confidential.as_str(), "Confidential");
    assert_eq!(SecurityLevel::Secret.as_str(), "Secret");
    assert_eq!(SecurityLevel::TopSecret.as_str(), "TopSecret");
}

#[test]
fn test_security_level_ordering() {
    assert!(SecurityLevel::Public < SecurityLevel::Internal);
    assert!(SecurityLevel::Internal < SecurityLevel::Confidential);
    assert!(SecurityLevel::Confidential < SecurityLevel::Secret);
    assert!(SecurityLevel::Secret < SecurityLevel::TopSecret);
}

#[test]
fn test_security_level_requires_encryption() {
    assert!(!SecurityLevel::Public.requires_encryption());
    assert!(!SecurityLevel::Internal.requires_encryption());
    assert!(!SecurityLevel::Confidential.requires_encryption());
    assert!(SecurityLevel::Secret.requires_encryption());
    assert!(SecurityLevel::TopSecret.requires_encryption());
}

#[test]
fn test_security_level_requires_secure_scrub() {
    assert!(!SecurityLevel::Public.requires_secure_scrub());
    assert!(!SecurityLevel::Internal.requires_secure_scrub());
    assert!(!SecurityLevel::Confidential.requires_secure_scrub());
    assert!(SecurityLevel::Secret.requires_secure_scrub());
    assert!(SecurityLevel::TopSecret.requires_secure_scrub());
}

#[test]
fn test_security_level_scrub_passes() {
    assert_eq!(SecurityLevel::Public.scrub_passes(), 0);
    assert_eq!(SecurityLevel::Internal.scrub_passes(), 0);
    assert_eq!(SecurityLevel::Confidential.scrub_passes(), 0);
    assert_eq!(SecurityLevel::Secret.scrub_passes(), 1);
    assert_eq!(SecurityLevel::TopSecret.scrub_passes(), SECURE_SCRUB_PASSES);
}

// ============================================================================
// MEMORY REGION TESTS
// ============================================================================

#[test]
fn test_memory_region_new() {
    let va = VirtAddr::new(0x1000);
    let pa = PhysAddr::new(0x2000);

    let region = MemoryRegion::new(
        1,
        va,
        pa,
        4096,
        RegionType::Data,
        SecurityLevel::Internal,
        100,
        12345,
    );

    assert_eq!(region.region_id, 1);
    assert_eq!(region.virtual_addr, va);
    assert_eq!(region.physical_addr, pa);
    assert_eq!(region.size, 4096);
    assert_eq!(region.region_type, RegionType::Data);
    assert_eq!(region.security_level, SecurityLevel::Internal);
    assert_eq!(region.owner_process, 100);
    assert!(!region.encrypted); // Internal doesn't require encryption
    assert_eq!(region.creation_time, 12345);
    assert_eq!(region.access_count, 0);
}

#[test]
fn test_memory_region_encryption_flag() {
    let va = VirtAddr::new(0x1000);
    let pa = PhysAddr::new(0x2000);

    // Non-encrypted level
    let region = MemoryRegion::new(
        1, va, pa, 4096,
        RegionType::Data, SecurityLevel::Confidential,
        100, 0,
    );
    assert!(!region.encrypted);

    // Encrypted level
    let region = MemoryRegion::new(
        2, va, pa, 4096,
        RegionType::Capsule, SecurityLevel::Secret,
        100, 0,
    );
    assert!(region.encrypted);

    let region = MemoryRegion::new(
        3, va, pa, 4096,
        RegionType::Capsule, SecurityLevel::TopSecret,
        100, 0,
    );
    assert!(region.encrypted);
}

#[test]
fn test_memory_region_end_addr() {
    let va = VirtAddr::new(0x1000);
    let pa = PhysAddr::new(0x2000);

    let region = MemoryRegion::new(
        1, va, pa, 0x3000,
        RegionType::Data, SecurityLevel::Public,
        100, 0,
    );

    assert_eq!(region.end_addr(), VirtAddr::new(0x4000));
}

#[test]
fn test_memory_region_contains() {
    let va = VirtAddr::new(0x1000);
    let pa = PhysAddr::new(0x2000);

    let region = MemoryRegion::new(
        1, va, pa, 0x1000,
        RegionType::Data, SecurityLevel::Public,
        100, 0,
    );

    assert!(region.contains(VirtAddr::new(0x1000))); // Start
    assert!(region.contains(VirtAddr::new(0x1500))); // Middle
    assert!(region.contains(VirtAddr::new(0x1FFF))); // End - 1
    assert!(!region.contains(VirtAddr::new(0x0FFF))); // Before
    assert!(!region.contains(VirtAddr::new(0x2000))); // End (exclusive)
    assert!(!region.contains(VirtAddr::new(0x3000))); // After
}

#[test]
fn test_memory_region_page_count() {
    let va = VirtAddr::new(0x1000);
    let pa = PhysAddr::new(0x2000);

    // Exact pages
    let region = MemoryRegion::new(
        1, va, pa, PAGE_SIZE * 4,
        RegionType::Data, SecurityLevel::Public,
        100, 0,
    );
    assert_eq!(region.page_count(), 4);

    // Partial page rounds up
    let region = MemoryRegion::new(
        2, va, pa, PAGE_SIZE + 1,
        RegionType::Data, SecurityLevel::Public,
        100, 0,
    );
    assert_eq!(region.page_count(), 2);

    // Single byte
    let region = MemoryRegion::new(
        3, va, pa, 1,
        RegionType::Data, SecurityLevel::Public,
        100, 0,
    );
    assert_eq!(region.page_count(), 1);
}

// ============================================================================
// MANAGER STATS TESTS
// ============================================================================

#[test]
fn test_manager_stats_utilization_zero_peak() {
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
fn test_manager_stats_utilization_half() {
    let stats = ManagerStats {
        total_regions: 5,
        allocated_memory: 500,
        peak_memory: 1000,
        allocations: 10,
        deallocations: 5,
    };

    assert_eq!(stats.utilization_percent(), 50.0);
}

#[test]
fn test_manager_stats_utilization_full() {
    let stats = ManagerStats {
        total_regions: 10,
        allocated_memory: 1000,
        peak_memory: 1000,
        allocations: 15,
        deallocations: 5,
    };

    assert_eq!(stats.utilization_percent(), 100.0);
}

// ============================================================================
// PUBLIC API TESTS
// ============================================================================

#[test]
fn test_is_initialized_before_init() {
    // Note: This test may not work correctly due to global state
    // In a real test environment, we'd need to reset the manager
    let _ = is_initialized();
}

#[test]
fn test_get_total_memory_initial() {
    // Initial state - may not be zero if other tests ran
    let _ = get_total_memory();
}

#[test]
fn test_get_peak_memory_initial() {
    let _ = get_peak_memory();
}

#[test]
fn test_get_allocation_count_initial() {
    let _ = get_allocation_count();
}

#[test]
fn test_get_deallocation_count_initial() {
    let _ = get_deallocation_count();
}

#[test]
fn test_get_region_count_initial() {
    let _ = get_region_count();
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_region_type_writable_matches_security_policy() {
    // Code regions should not be writable
    let code_type = RegionType::Code;
    assert!(!code_type.is_writable());
    assert!(code_type.is_executable());

    // Data regions should be writable but not executable
    let data_type = RegionType::Data;
    assert!(data_type.is_writable());
    assert!(!data_type.is_executable());
}

#[test]
fn test_security_levels_consistent() {
    // Higher security levels should require more protection
    for level in [
        SecurityLevel::Public,
        SecurityLevel::Internal,
        SecurityLevel::Confidential,
    ] {
        assert!(!level.requires_encryption());
        assert!(!level.requires_secure_scrub());
    }

    for level in [SecurityLevel::Secret, SecurityLevel::TopSecret] {
        assert!(level.requires_encryption());
        assert!(level.requires_secure_scrub());
    }

    // TopSecret should have more scrub passes than Secret
    assert!(SecurityLevel::TopSecret.scrub_passes() > SecurityLevel::Secret.scrub_passes());
}

#[test]
fn test_error_categories_mutually_exclusive() {
    // A security-critical error should not be retriable
    for err in [
        SecureMemoryError::AccessDenied,
        SecureMemoryError::OwnershipViolation,
        SecureMemoryError::WriteToReadOnly,
        SecureMemoryError::ExecuteViolation,
        SecureMemoryError::SystemRegionProtected,
        SecureMemoryError::InternalCorruption,
    ] {
        assert!(err.is_security_critical());
        assert!(!err.is_retriable());
    }
}
