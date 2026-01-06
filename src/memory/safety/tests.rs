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

// ============================================================================
// CONSTANT TESTS
// ============================================================================

#[test]
fn test_canary_constants() {
    assert_eq!(CANARY_BASE, 0xDEADBEEFCAFEBABE);
    assert_eq!(CANARY_MIX_CONSTANT, 0x9e3779b97f4a7c15);
}

#[test]
fn test_detection_constants() {
    assert_eq!(ACCESS_HISTORY_MAX, 1000);
    assert_eq!(OVERFLOW_DETECTION_WINDOW, 10);
    assert_eq!(SEQUENTIAL_WRITE_THRESHOLD, 5);
    assert_eq!(UAF_DETECTION_WINDOW, 50);
}

// ============================================================================
// PROTECTION LEVEL TESTS
// ============================================================================

#[test]
fn test_protection_level_ordering() {
    assert!(ProtectionLevel::None < ProtectionLevel::Basic);
    assert!(ProtectionLevel::Basic < ProtectionLevel::Paranoid);
    assert!(ProtectionLevel::Paranoid < ProtectionLevel::Cryptographic);
}

#[test]
fn test_protection_level_equality() {
    assert_eq!(ProtectionLevel::Basic, ProtectionLevel::Basic);
    assert_ne!(ProtectionLevel::Basic, ProtectionLevel::Paranoid);
}

// ============================================================================
// MEMORY REGION TESTS
// ============================================================================

#[test]
fn test_memory_region_creation() {
    let region = MemoryRegion::new(
        0x1000,
        0x2000,
        "Test Region",
        ProtectionLevel::Basic,
        true,
        false,
        false,
        false,
    );

    assert_eq!(region.start, 0x1000);
    assert_eq!(region.end, 0x2000);
    assert_eq!(region.name, "Test Region");
    assert_eq!(region.protection, ProtectionLevel::Basic);
    assert!(region.read_allowed);
    assert!(!region.write_allowed);
    assert!(!region.execute_allowed);
    assert!(!region.user_accessible);
}

#[test]
fn test_memory_region_size() {
    let region = MemoryRegion::new(
        0x1000,
        0x3000,
        "Test",
        ProtectionLevel::None,
        true,
        true,
        true,
        true,
    );

    assert_eq!(region.size(), 0x2000);
}

#[test]
fn test_memory_region_contains() {
    let region = MemoryRegion::new(
        0x1000,
        0x2000,
        "Test",
        ProtectionLevel::None,
        true,
        true,
        true,
        true,
    );

    assert!(region.contains(0x1000));
    assert!(region.contains(0x1500));
    assert!(region.contains(0x1FFF));
    assert!(!region.contains(0x0FFF));
    assert!(!region.contains(0x2000));
}

#[test]
fn test_memory_region_contains_range() {
    let region = MemoryRegion::new(
        0x1000,
        0x3000,
        "Test",
        ProtectionLevel::None,
        true,
        true,
        true,
        true,
    );

    assert!(region.contains_range(0x1000, 0x1000));
    assert!(region.contains_range(0x1500, 0x500));
    assert!(!region.contains_range(0x2500, 0x1000));
    assert!(!region.contains_range(0x0500, 0x1000));
}

// ============================================================================
// ACCESS TYPE TESTS
// ============================================================================

#[test]
fn test_access_type_equality() {
    assert_eq!(AccessType::Read, AccessType::Read);
    assert_eq!(AccessType::Write, AccessType::Write);
    assert_eq!(AccessType::Execute, AccessType::Execute);
    assert_ne!(AccessType::Read, AccessType::Write);
}

// ============================================================================
// GUARD TYPE TESTS
// ============================================================================

#[test]
fn test_guard_type_equality() {
    assert_eq!(GuardType::StackGuard, GuardType::StackGuard);
    assert_ne!(GuardType::StackGuard, GuardType::HeapGuard);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_memory_error_as_str() {
    assert_eq!(
        MemoryError::NotInitialized.as_str(),
        "Memory safety not initialized"
    );
    assert_eq!(MemoryError::NullPointer.as_str(), "Null pointer access");
    assert_eq!(MemoryError::AddressOverflow.as_str(), "Address overflow");
    assert_eq!(MemoryError::BadAlignment.as_str(), "Bad memory alignment");
    assert_eq!(
        MemoryError::UnmappedAccess.as_str(),
        "Access to unmapped memory"
    );
}

#[test]
fn test_memory_error_is_security_violation() {
    assert!(MemoryError::ReadViolation.is_security_violation());
    assert!(MemoryError::WriteViolation.is_security_violation());
    assert!(MemoryError::ExecuteViolation.is_security_violation());
    assert!(MemoryError::CorruptionDetected.is_security_violation());
    assert!(!MemoryError::NotInitialized.is_security_violation());
}

#[test]
fn test_memory_error_is_potential_attack() {
    assert!(MemoryError::NullPointer.is_potential_attack());
    assert!(MemoryError::AddressOverflow.is_potential_attack());
    assert!(MemoryError::CorruptionDetected.is_potential_attack());
    assert!(!MemoryError::NotInitialized.is_potential_attack());
}

#[test]
fn test_memory_error_is_recoverable() {
    assert!(MemoryError::NotInitialized.is_recoverable());
    assert!(MemoryError::BadAlignment.is_recoverable());
    assert!(!MemoryError::CorruptionDetected.is_recoverable());
}

#[test]
fn test_memory_error_display() {
    let error = MemoryError::NullPointer;
    let msg = format!("{}", error);
    assert_eq!(msg, "Null pointer access");
}

// ============================================================================
// PREDEFINED REGIONS TESTS
// ============================================================================

#[test]
fn test_predefined_regions_count() {
    assert_eq!(REGIONS.len(), 5);
}

#[test]
fn test_predefined_regions_names() {
    let names: Vec<&str> = REGIONS.iter().map(|r| r.name).collect();
    assert!(names.contains(&"Kernel Text"));
    assert!(names.contains(&"Kernel Heap"));
    assert!(names.contains(&"Direct Map"));
    assert!(names.contains(&"MMIO Space"));
    assert!(names.contains(&"VGA Buffer"));
}

#[test]
fn test_kernel_text_region() {
    let kernel_text = REGIONS.iter().find(|r| r.name == "Kernel Text").unwrap();

    assert!(kernel_text.read_allowed);
    assert!(!kernel_text.write_allowed);
    assert!(kernel_text.execute_allowed);
    assert!(!kernel_text.user_accessible);
    assert_eq!(kernel_text.protection, ProtectionLevel::Cryptographic);
}

#[test]
fn test_kernel_heap_region() {
    let kernel_heap = REGIONS.iter().find(|r| r.name == "Kernel Heap").unwrap();

    assert!(kernel_heap.read_allowed);
    assert!(kernel_heap.write_allowed);
    assert!(!kernel_heap.execute_allowed);
    assert!(!kernel_heap.user_accessible);
    assert_eq!(kernel_heap.protection, ProtectionLevel::Paranoid);
}

// ============================================================================
// GUARD REGION TESTS
// ============================================================================

#[test]
fn test_guard_region_creation() {
    let guard = GuardRegion {
        start: 0x1000,
        end: 0x2000,
        region_type: GuardType::StackGuard,
    };

    assert_eq!(guard.start, 0x1000);
    assert_eq!(guard.end, 0x2000);
    assert_eq!(guard.region_type, GuardType::StackGuard);
}

// ============================================================================
// MEMORY STATS TESTS
// ============================================================================

#[test]
fn test_memory_stats_structure() {
    let stats = MemoryStats {
        violations: 5,
        protection_level: ProtectionLevel::Paranoid,
        regions_count: 10,
        access_patterns: 100,
    };

    assert_eq!(stats.violations, 5);
    assert_eq!(stats.protection_level, ProtectionLevel::Paranoid);
    assert_eq!(stats.regions_count, 10);
    assert_eq!(stats.access_patterns, 100);
}

// ============================================================================
// ACCESS PATTERN TESTS
// ============================================================================

#[test]
fn test_access_pattern_creation() {
    let pattern = AccessPattern {
        addr: 0x1000,
        size: 64,
        timestamp: 12345,
        access_type: AccessType::Write,
    };

    assert_eq!(pattern.addr, 0x1000);
    assert_eq!(pattern.size, 64);
    assert_eq!(pattern.timestamp, 12345);
    assert_eq!(pattern.access_type, AccessType::Write);
}
