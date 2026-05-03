// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Secure memory region tests

use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::secure_memory::{
    ManagerStats, MemoryRegion, RegionType, SecureMemoryError, SecurityLevel, DEFAULT_ALIGNMENT,
    ENCRYPTION_THRESHOLD_LEVEL, INITIAL_REGION_ID, INVALID_PROCESS_ID, INVALID_REGION_ID,
    KERNEL_PROCESS_ID, MAX_ALLOCATION_COUNT, MAX_ALLOCATION_SIZE, MAX_MEMORY_USAGE, MAX_REGIONS,
    MIN_ALLOCATION_SIZE, PAGE_SIZE, PERM_EXECUTE, PERM_READ, PERM_USER, PERM_WRITE,
    REGION_TYPE_CAPSULE, REGION_TYPE_CODE, REGION_TYPE_DATA, REGION_TYPE_DEVICE, REGION_TYPE_HEAP,
    REGION_TYPE_STACK, SECURE_SCRUB_PASSES, SECURE_SCRUB_PATTERN, SECURITY_LEVEL_CONFIDENTIAL,
    SECURITY_LEVEL_INTERNAL, SECURITY_LEVEL_PUBLIC, SECURITY_LEVEL_SECRET,
    SECURITY_LEVEL_TOP_SECRET,
};
use crate::test::framework::TestResult;

pub(crate) fn test_region_type_code() -> TestResult {
    let rt = RegionType::Code;
    if rt.as_u8() != REGION_TYPE_CODE {
        return TestResult::Fail;
    }
    if rt.as_str() != "Code" {
        return TestResult::Fail;
    }
    if rt.is_writable() {
        return TestResult::Fail;
    }
    if !rt.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_data() -> TestResult {
    let rt = RegionType::Data;
    if rt.as_u8() != REGION_TYPE_DATA {
        return TestResult::Fail;
    }
    if rt.as_str() != "Data" {
        return TestResult::Fail;
    }
    if !rt.is_writable() {
        return TestResult::Fail;
    }
    if rt.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_stack() -> TestResult {
    let rt = RegionType::Stack;
    if rt.as_u8() != REGION_TYPE_STACK {
        return TestResult::Fail;
    }
    if rt.as_str() != "Stack" {
        return TestResult::Fail;
    }
    if !rt.is_writable() {
        return TestResult::Fail;
    }
    if rt.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_heap() -> TestResult {
    let rt = RegionType::Heap;
    if rt.as_u8() != REGION_TYPE_HEAP {
        return TestResult::Fail;
    }
    if rt.as_str() != "Heap" {
        return TestResult::Fail;
    }
    if !rt.is_writable() {
        return TestResult::Fail;
    }
    if rt.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_device() -> TestResult {
    let rt = RegionType::Device;
    if rt.as_u8() != REGION_TYPE_DEVICE {
        return TestResult::Fail;
    }
    if rt.as_str() != "Device" {
        return TestResult::Fail;
    }
    if !rt.is_writable() {
        return TestResult::Fail;
    }
    if rt.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_capsule() -> TestResult {
    let rt = RegionType::Capsule;
    if rt.as_u8() != REGION_TYPE_CAPSULE {
        return TestResult::Fail;
    }
    if rt.as_str() != "Capsule" {
        return TestResult::Fail;
    }
    if rt.is_writable() {
        return TestResult::Fail;
    }
    if rt.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_equality() -> TestResult {
    if RegionType::Code != RegionType::Code {
        return TestResult::Fail;
    }
    if RegionType::Code == RegionType::Data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_clone() -> TestResult {
    let rt = RegionType::Stack;
    let cloned = rt.clone();
    if rt != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_public() -> TestResult {
    let sl = SecurityLevel::Public;
    if sl.as_u8() != SECURITY_LEVEL_PUBLIC {
        return TestResult::Fail;
    }
    if sl.as_str() != "Public" {
        return TestResult::Fail;
    }
    if sl.requires_encryption() {
        return TestResult::Fail;
    }
    if sl.requires_secure_scrub() {
        return TestResult::Fail;
    }
    if sl.scrub_passes() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_internal() -> TestResult {
    let sl = SecurityLevel::Internal;
    if sl.as_u8() != SECURITY_LEVEL_INTERNAL {
        return TestResult::Fail;
    }
    if sl.as_str() != "Internal" {
        return TestResult::Fail;
    }
    if sl.requires_encryption() {
        return TestResult::Fail;
    }
    if sl.requires_secure_scrub() {
        return TestResult::Fail;
    }
    if sl.scrub_passes() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_confidential() -> TestResult {
    let sl = SecurityLevel::Confidential;
    if sl.as_u8() != SECURITY_LEVEL_CONFIDENTIAL {
        return TestResult::Fail;
    }
    if sl.as_str() != "Confidential" {
        return TestResult::Fail;
    }
    if sl.requires_encryption() {
        return TestResult::Fail;
    }
    if sl.requires_secure_scrub() {
        return TestResult::Fail;
    }
    if sl.scrub_passes() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_secret() -> TestResult {
    let sl = SecurityLevel::Secret;
    if sl.as_u8() != SECURITY_LEVEL_SECRET {
        return TestResult::Fail;
    }
    if sl.as_str() != "Secret" {
        return TestResult::Fail;
    }
    if !sl.requires_encryption() {
        return TestResult::Fail;
    }
    if !sl.requires_secure_scrub() {
        return TestResult::Fail;
    }
    if sl.scrub_passes() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_top_secret() -> TestResult {
    let sl = SecurityLevel::TopSecret;
    if sl.as_u8() != SECURITY_LEVEL_TOP_SECRET {
        return TestResult::Fail;
    }
    if sl.as_str() != "TopSecret" {
        return TestResult::Fail;
    }
    if !sl.requires_encryption() {
        return TestResult::Fail;
    }
    if !sl.requires_secure_scrub() {
        return TestResult::Fail;
    }
    if sl.scrub_passes() != SECURE_SCRUB_PASSES {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_ordering() -> TestResult {
    if SecurityLevel::Public >= SecurityLevel::Internal {
        return TestResult::Fail;
    }
    if SecurityLevel::Internal >= SecurityLevel::Confidential {
        return TestResult::Fail;
    }
    if SecurityLevel::Confidential >= SecurityLevel::Secret {
        return TestResult::Fail;
    }
    if SecurityLevel::Secret >= SecurityLevel::TopSecret {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_equality() -> TestResult {
    if SecurityLevel::Secret != SecurityLevel::Secret {
        return TestResult::Fail;
    }
    if SecurityLevel::Secret == SecurityLevel::TopSecret {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_clone() -> TestResult {
    let sl = SecurityLevel::Confidential;
    let cloned = sl.clone();
    if sl != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_new() -> TestResult {
    let va = VirtAddr::new(0x1000);
    let pa = PhysAddr::new(0x2000);
    let region =
        MemoryRegion::new(1, va, pa, 4096, RegionType::Data, SecurityLevel::Internal, 42, 1000);
    if region.region_id != 1 {
        return TestResult::Fail;
    }
    if region.virtual_addr != va {
        return TestResult::Fail;
    }
    if region.physical_addr != pa {
        return TestResult::Fail;
    }
    if region.size != 4096 {
        return TestResult::Fail;
    }
    if region.region_type != RegionType::Data {
        return TestResult::Fail;
    }
    if region.security_level != SecurityLevel::Internal {
        return TestResult::Fail;
    }
    if region.owner_process != 42 {
        return TestResult::Fail;
    }
    if region.encrypted {
        return TestResult::Fail;
    }
    if region.creation_time != 1000 {
        return TestResult::Fail;
    }
    if region.access_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_encrypted_secret() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        RegionType::Data,
        SecurityLevel::Secret,
        42,
        1000,
    );
    if !region.encrypted {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_encrypted_top_secret() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        RegionType::Data,
        SecurityLevel::TopSecret,
        42,
        1000,
    );
    if !region.encrypted {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_not_encrypted_public() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        RegionType::Data,
        SecurityLevel::Public,
        42,
        1000,
    );
    if region.encrypted {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_end_addr() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        RegionType::Data,
        SecurityLevel::Public,
        42,
        1000,
    );
    if region.end_addr() != VirtAddr::new(0x2000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_contains_inside() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        RegionType::Data,
        SecurityLevel::Public,
        42,
        1000,
    );
    if !region.contains(VirtAddr::new(0x1000)) {
        return TestResult::Fail;
    }
    if !region.contains(VirtAddr::new(0x1FFF)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_contains_outside() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        RegionType::Data,
        SecurityLevel::Public,
        42,
        1000,
    );
    if region.contains(VirtAddr::new(0x0FFF)) {
        return TestResult::Fail;
    }
    if region.contains(VirtAddr::new(0x2000)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_page_count_single() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        RegionType::Data,
        SecurityLevel::Public,
        42,
        1000,
    );
    if region.page_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_page_count_multiple() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        8192,
        RegionType::Data,
        SecurityLevel::Public,
        42,
        1000,
    );
    if region.page_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_page_count_partial() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4097,
        RegionType::Data,
        SecurityLevel::Public,
        42,
        1000,
    );
    if region.page_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_clone() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        RegionType::Data,
        SecurityLevel::Internal,
        42,
        1000,
    );
    let cloned = region.clone();
    if region.region_id != cloned.region_id {
        return TestResult::Fail;
    }
    if region.virtual_addr != cloned.virtual_addr {
        return TestResult::Fail;
    }
    if region.size != cloned.size {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manager_stats_utilization_percent() -> TestResult {
    let stats = ManagerStats {
        total_regions: 10,
        allocated_memory: 50,
        peak_memory: 100,
        allocations: 20,
        deallocations: 10,
    };
    let util = stats.utilization_percent();
    if (util - 50.0).abs() >= 0.001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manager_stats_utilization_percent_zero_peak() -> TestResult {
    let stats = ManagerStats {
        total_regions: 0,
        allocated_memory: 0,
        peak_memory: 0,
        allocations: 0,
        deallocations: 0,
    };
    if stats.utilization_percent() != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manager_stats_clone() -> TestResult {
    let stats = ManagerStats {
        total_regions: 5,
        allocated_memory: 1000,
        peak_memory: 2000,
        allocations: 10,
        deallocations: 5,
    };
    let cloned = stats.clone();
    if stats.total_regions != cloned.total_regions {
        return TestResult::Fail;
    }
    if stats.allocated_memory != cloned.allocated_memory {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_memory_error_variants() -> TestResult {
    if SecureMemoryError::NotInitialized != SecureMemoryError::NotInitialized {
        return TestResult::Fail;
    }
    if SecureMemoryError::AlreadyInitialized != SecureMemoryError::AlreadyInitialized {
        return TestResult::Fail;
    }
    if SecureMemoryError::InvalidSize != SecureMemoryError::InvalidSize {
        return TestResult::Fail;
    }
    if SecureMemoryError::AllocationFailed != SecureMemoryError::AllocationFailed {
        return TestResult::Fail;
    }
    if SecureMemoryError::AddressNotFound != SecureMemoryError::AddressNotFound {
        return TestResult::Fail;
    }
    if SecureMemoryError::RegionNotFound != SecureMemoryError::RegionNotFound {
        return TestResult::Fail;
    }
    if SecureMemoryError::TranslationFailed != SecureMemoryError::TranslationFailed {
        return TestResult::Fail;
    }
    if SecureMemoryError::ZeroingFailed != SecureMemoryError::ZeroingFailed {
        return TestResult::Fail;
    }
    if SecureMemoryError::AccessDenied != SecureMemoryError::AccessDenied {
        return TestResult::Fail;
    }
    if SecureMemoryError::InvalidSecurityLevel != SecureMemoryError::InvalidSecurityLevel {
        return TestResult::Fail;
    }
    if SecureMemoryError::InvalidRegionType != SecureMemoryError::InvalidRegionType {
        return TestResult::Fail;
    }
    if SecureMemoryError::RegionLimitExceeded != SecureMemoryError::RegionLimitExceeded {
        return TestResult::Fail;
    }
    if SecureMemoryError::OwnershipViolation != SecureMemoryError::OwnershipViolation {
        return TestResult::Fail;
    }
    if SecureMemoryError::WriteToReadOnly != SecureMemoryError::WriteToReadOnly {
        return TestResult::Fail;
    }
    if SecureMemoryError::ExecuteViolation != SecureMemoryError::ExecuteViolation {
        return TestResult::Fail;
    }
    if SecureMemoryError::AlreadyDeallocated != SecureMemoryError::AlreadyDeallocated {
        return TestResult::Fail;
    }
    if SecureMemoryError::InvalidAddress != SecureMemoryError::InvalidAddress {
        return TestResult::Fail;
    }
    if SecureMemoryError::SystemRegionProtected != SecureMemoryError::SystemRegionProtected {
        return TestResult::Fail;
    }
    if SecureMemoryError::InternalCorruption != SecureMemoryError::InternalCorruption {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_memory_error_clone() -> TestResult {
    let err = SecureMemoryError::AccessDenied;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_limits_constants() -> TestResult {
    if MIN_ALLOCATION_SIZE != 1 {
        return TestResult::Fail;
    }
    if MAX_ALLOCATION_SIZE != 1024 * 1024 * 1024 {
        return TestResult::Fail;
    }
    if DEFAULT_ALIGNMENT != 16 {
        return TestResult::Fail;
    }
    if PAGE_SIZE != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scrub_constants() -> TestResult {
    if SECURE_SCRUB_PATTERN != 0xAA {
        return TestResult::Fail;
    }
    if SECURE_SCRUB_PASSES != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_constants() -> TestResult {
    if MAX_ALLOCATION_COUNT != u64::MAX - 1 {
        return TestResult::Fail;
    }
    if MAX_MEMORY_USAGE != u64::MAX - 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_process_id_constants() -> TestResult {
    if KERNEL_PROCESS_ID != 0 {
        return TestResult::Fail;
    }
    if INVALID_PROCESS_ID != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_permission_constants() -> TestResult {
    if PERM_READ != 0x01 {
        return TestResult::Fail;
    }
    if PERM_WRITE != 0x02 {
        return TestResult::Fail;
    }
    if PERM_EXECUTE != 0x04 {
        return TestResult::Fail;
    }
    if PERM_USER != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_constants() -> TestResult {
    if SECURITY_LEVEL_PUBLIC != 0 {
        return TestResult::Fail;
    }
    if SECURITY_LEVEL_INTERNAL != 1 {
        return TestResult::Fail;
    }
    if SECURITY_LEVEL_CONFIDENTIAL != 2 {
        return TestResult::Fail;
    }
    if SECURITY_LEVEL_SECRET != 3 {
        return TestResult::Fail;
    }
    if SECURITY_LEVEL_TOP_SECRET != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_encryption_threshold() -> TestResult {
    if ENCRYPTION_THRESHOLD_LEVEL != SECURITY_LEVEL_SECRET {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_constants() -> TestResult {
    if REGION_TYPE_CODE != 0 {
        return TestResult::Fail;
    }
    if REGION_TYPE_DATA != 1 {
        return TestResult::Fail;
    }
    if REGION_TYPE_STACK != 2 {
        return TestResult::Fail;
    }
    if REGION_TYPE_HEAP != 3 {
        return TestResult::Fail;
    }
    if REGION_TYPE_DEVICE != 4 {
        return TestResult::Fail;
    }
    if REGION_TYPE_CAPSULE != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_id_constants() -> TestResult {
    if INITIAL_REGION_ID != 1 {
        return TestResult::Fail;
    }
    if MAX_REGIONS != 65536 {
        return TestResult::Fail;
    }
    if INVALID_REGION_ID != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_all_variants() -> TestResult {
    let levels = [
        SecurityLevel::Public,
        SecurityLevel::Internal,
        SecurityLevel::Confidential,
        SecurityLevel::Secret,
        SecurityLevel::TopSecret,
    ];
    for i in 0..levels.len() {
        for j in (i + 1)..levels.len() {
            if levels[i] >= levels[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_same_value() -> TestResult {
    let rt1 = RegionType::Code;
    let rt2 = RegionType::Code;
    if rt1 != rt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_same_value() -> TestResult {
    let sl1 = SecurityLevel::Secret;
    let sl2 = SecurityLevel::Secret;
    if sl1 != sl2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_large_size() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        1024 * 1024 * 1024,
        RegionType::Heap,
        SecurityLevel::Public,
        42,
        1000,
    );
    if region.page_count() != 262144 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_all_writable() -> TestResult {
    if !RegionType::Data.is_writable() {
        return TestResult::Fail;
    }
    if !RegionType::Stack.is_writable() {
        return TestResult::Fail;
    }
    if !RegionType::Heap.is_writable() {
        return TestResult::Fail;
    }
    if !RegionType::Device.is_writable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_all_not_writable() -> TestResult {
    if RegionType::Code.is_writable() {
        return TestResult::Fail;
    }
    if RegionType::Capsule.is_writable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_all_executable() -> TestResult {
    if !RegionType::Code.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_all_not_executable() -> TestResult {
    if RegionType::Data.is_executable() {
        return TestResult::Fail;
    }
    if RegionType::Stack.is_executable() {
        return TestResult::Fail;
    }
    if RegionType::Heap.is_executable() {
        return TestResult::Fail;
    }
    if RegionType::Device.is_executable() {
        return TestResult::Fail;
    }
    if RegionType::Capsule.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manager_stats_fields() -> TestResult {
    let stats = ManagerStats {
        total_regions: 100,
        allocated_memory: 1024 * 1024,
        peak_memory: 2 * 1024 * 1024,
        allocations: 150,
        deallocations: 50,
    };
    if stats.total_regions != 100 {
        return TestResult::Fail;
    }
    if stats.allocated_memory != 1024 * 1024 {
        return TestResult::Fail;
    }
    if stats.peak_memory != 2 * 1024 * 1024 {
        return TestResult::Fail;
    }
    if stats.allocations != 150 {
        return TestResult::Fail;
    }
    if stats.deallocations != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_region_boundary_address() -> TestResult {
    let region = MemoryRegion::new(
        1,
        VirtAddr::new(0xFFFF_FFFF_FFFF_F000),
        PhysAddr::new(0x1000),
        4096,
        RegionType::Data,
        SecurityLevel::Public,
        0,
        0,
    );
    if region.end_addr() != VirtAddr::new(0xFFFF_FFFF_FFFF_F000u64.wrapping_add(4096)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_copy() -> TestResult {
    let sl1 = SecurityLevel::Confidential;
    let sl2 = sl1;
    if sl1 != sl2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_region_type_copy() -> TestResult {
    let rt1 = RegionType::Heap;
    let rt2 = rt1;
    if rt1 != rt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
