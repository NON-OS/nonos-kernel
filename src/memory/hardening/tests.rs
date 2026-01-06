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
fn test_cr4_constants() {
    assert_eq!(CR4_SMEP, 1 << 20);
    assert_eq!(CR4_SMAP, 1 << 21);
    assert_eq!(CR4_REQUIRED_BITS, CR4_SMEP | CR4_SMAP);
}

#[test]
fn test_corruption_pattern() {
    assert_eq!(CORRUPTION_PATTERN, 0xDEADBEEFCAFEBABE);
}

#[test]
fn test_nop_constants() {
    assert_eq!(NOP_INSTRUCTION, 0x90);
    assert_eq!(NOP_SLED_CHECK_SIZE, 16);
}

// ============================================================================
// GUARD TYPE TESTS
// ============================================================================

#[test]
fn test_guard_type_equality() {
    assert_eq!(GuardType::StackGuard, GuardType::StackGuard);
    assert_eq!(GuardType::HeapGuard, GuardType::HeapGuard);
    assert_eq!(GuardType::KernelGuard, GuardType::KernelGuard);
    assert_eq!(GuardType::UserGuard, GuardType::UserGuard);
    assert_ne!(GuardType::StackGuard, GuardType::HeapGuard);
}

// ============================================================================
// GUARD PAGE TESTS
// ============================================================================

#[test]
fn test_guard_page_creation() {
    let guard = GuardPage {
        addr: VirtAddr::new(0x1000),
        size: 4096,
        protection_type: GuardType::StackGuard,
    };

    assert_eq!(guard.addr.as_u64(), 0x1000);
    assert_eq!(guard.size, 4096);
    assert_eq!(guard.protection_type, GuardType::StackGuard);
}

// ============================================================================
// STACK CANARY TESTS
// ============================================================================

#[test]
fn test_stack_canary_structure() {
    let canary = StackCanary {
        value: 0xDEADBEEF,
        stack_base: VirtAddr::new(0x10000),
        stack_size: 0x4000,
    };

    assert_eq!(canary.value, 0xDEADBEEF);
    assert_eq!(canary.stack_base.as_u64(), 0x10000);
    assert_eq!(canary.stack_size, 0x4000);
}

// ============================================================================
// ALLOCATION INFO TESTS
// ============================================================================

#[test]
fn test_allocation_info_creation() {
    let info = AllocationInfo {
        size: 1024,
        timestamp: 12345,
        allocation_id: 1,
        freed: false,
    };

    assert_eq!(info.size, 1024);
    assert_eq!(info.timestamp, 12345);
    assert_eq!(info.allocation_id, 1);
    assert!(!info.freed);
}

#[test]
fn test_allocation_info_freed_state() {
    let mut info = AllocationInfo {
        size: 1024,
        timestamp: 12345,
        allocation_id: 1,
        freed: false,
    };

    assert!(!info.freed);
    info.freed = true;
    assert!(info.freed);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_hardening_error_as_str() {
    assert_eq!(
        HardeningError::NotInitialized.as_str(),
        "Hardening not initialized"
    );
    assert_eq!(
        HardeningError::WXViolation.as_str(),
        "W^X violation: memory cannot be both writable and executable"
    );
    assert_eq!(
        HardeningError::GuardPageViolation.as_str(),
        "Guard page access detected"
    );
    assert_eq!(
        HardeningError::StackOverflow.as_str(),
        "Stack overflow detected"
    );
    assert_eq!(
        HardeningError::HeapCorruption.as_str(),
        "Heap corruption detected"
    );
    assert_eq!(HardeningError::DoubleFree.as_str(), "Double free detected");
    assert_eq!(
        HardeningError::UseAfterFree.as_str(),
        "Use after free detected"
    );
}

#[test]
fn test_hardening_error_is_security_violation() {
    assert!(HardeningError::WXViolation.is_security_violation());
    assert!(HardeningError::GuardPageViolation.is_security_violation());
    assert!(HardeningError::StackOverflow.is_security_violation());
    assert!(HardeningError::HeapCorruption.is_security_violation());
    assert!(HardeningError::DoubleFree.is_security_violation());
    assert!(HardeningError::UseAfterFree.is_security_violation());
    assert!(HardeningError::CanaryCorrupted.is_security_violation());
    assert!(!HardeningError::NotInitialized.is_security_violation());
}

#[test]
fn test_hardening_error_is_fatal() {
    assert!(HardeningError::StackOverflow.is_fatal());
    assert!(HardeningError::HeapCorruption.is_fatal());
    assert!(HardeningError::CanaryCorrupted.is_fatal());
    assert!(!HardeningError::WXViolation.is_fatal());
    assert!(!HardeningError::DoubleFree.is_fatal());
}

#[test]
fn test_hardening_error_is_memory_safety_issue() {
    assert!(HardeningError::DoubleFree.is_memory_safety_issue());
    assert!(HardeningError::UseAfterFree.is_memory_safety_issue());
    assert!(HardeningError::HeapCorruption.is_memory_safety_issue());
    assert!(!HardeningError::WXViolation.is_memory_safety_issue());
    assert!(!HardeningError::StackOverflow.is_memory_safety_issue());
}

#[test]
fn test_hardening_error_display() {
    let error = HardeningError::DoubleFree;
    let msg = format!("{}", error);
    assert_eq!(msg, "Double free detected");
}

// ============================================================================
// STATS TESTS
// ============================================================================

#[test]
fn test_hardening_stats_new() {
    let stats = HardeningStats::new();
    assert_eq!(stats.guard_violations(), 0);
    assert_eq!(stats.wx_violations(), 0);
    assert_eq!(stats.stack_overflows(), 0);
    assert_eq!(stats.heap_corruptions(), 0);
    assert_eq!(stats.double_frees(), 0);
    assert_eq!(stats.use_after_free(), 0);
}

#[test]
fn test_hardening_stats_increment() {
    let stats = HardeningStats::new();

    stats.increment_guard_violations();
    assert_eq!(stats.guard_violations(), 1);

    stats.increment_wx_violations();
    assert_eq!(stats.wx_violations(), 1);

    stats.increment_stack_overflows();
    assert_eq!(stats.stack_overflows(), 1);

    stats.increment_heap_corruptions();
    assert_eq!(stats.heap_corruptions(), 1);

    stats.increment_double_frees();
    assert_eq!(stats.double_frees(), 1);

    stats.increment_use_after_free();
    assert_eq!(stats.use_after_free(), 1);
}

// ============================================================================
// STATS SNAPSHOT TESTS
// ============================================================================

#[test]
fn test_hardening_stats_snapshot() {
    let snapshot = HardeningStatsSnapshot {
        guard_violations: 1,
        wx_violations: 2,
        stack_overflows: 3,
        heap_corruptions: 4,
        double_frees: 5,
        use_after_free: 6,
        total_guard_pages: 10,
        active_canaries: 5,
        tracked_allocations: 100,
    };

    assert_eq!(snapshot.guard_violations, 1);
    assert_eq!(snapshot.wx_violations, 2);
    assert_eq!(snapshot.stack_overflows, 3);
    assert_eq!(snapshot.heap_corruptions, 4);
    assert_eq!(snapshot.double_frees, 5);
    assert_eq!(snapshot.use_after_free, 6);
    assert_eq!(snapshot.total_guard_pages, 10);
    assert_eq!(snapshot.active_canaries, 5);
    assert_eq!(snapshot.tracked_allocations, 100);
}
