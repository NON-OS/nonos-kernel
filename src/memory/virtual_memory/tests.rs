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
fn test_user_address_constants() {
    assert_eq!(USER_HEAP_START, 0x10000000);
    assert_eq!(USER_STACK_BOTTOM, 0x70000000);
    assert_eq!(USER_STACK_TOP, 0x80000000);
    assert_eq!(USER_MMAP_START, 0x40000000);
    assert_eq!(SHARED_MEMORY_START, 0x50000000);
}

#[test]
fn test_page_fault_constants() {
    assert_eq!(PF_PRESENT, 0x01);
    assert_eq!(PF_WRITE, 0x02);
    assert_eq!(PF_USER, 0x04);
    assert_eq!(PF_RESERVED, 0x08);
    assert_eq!(PF_INSTRUCTION, 0x10);
}

// ============================================================================
// VM PROTECTION TESTS
// ============================================================================

#[test]
fn test_vm_protection_equality() {
    assert_eq!(VmProtection::None, VmProtection::None);
    assert_eq!(VmProtection::Read, VmProtection::Read);
    assert_eq!(VmProtection::ReadWrite, VmProtection::ReadWrite);
    assert_ne!(VmProtection::Read, VmProtection::ReadWrite);
}

#[test]
fn test_vm_protection_is_readable() {
    assert!(!VmProtection::None.is_readable());
    assert!(VmProtection::Read.is_readable());
    assert!(VmProtection::ReadWrite.is_readable());
    assert!(VmProtection::ReadExecute.is_readable());
    assert!(VmProtection::ReadWriteExecute.is_readable());
}

#[test]
fn test_vm_protection_is_writable() {
    assert!(!VmProtection::None.is_writable());
    assert!(!VmProtection::Read.is_writable());
    assert!(VmProtection::ReadWrite.is_writable());
    assert!(!VmProtection::ReadExecute.is_writable());
    assert!(VmProtection::ReadWriteExecute.is_writable());
}

#[test]
fn test_vm_protection_is_executable() {
    assert!(!VmProtection::None.is_executable());
    assert!(!VmProtection::Read.is_executable());
    assert!(!VmProtection::ReadWrite.is_executable());
    assert!(VmProtection::ReadExecute.is_executable());
    assert!(VmProtection::ReadWriteExecute.is_executable());
}

// ============================================================================
// VM TYPE TESTS
// ============================================================================

#[test]
fn test_vm_type_equality() {
    assert_eq!(VmType::Anonymous, VmType::Anonymous);
    assert_eq!(VmType::Stack, VmType::Stack);
    assert_ne!(VmType::Heap, VmType::Stack);
}

#[test]
fn test_vm_type_is_zero_initialized() {
    assert!(VmType::Anonymous.is_zero_initialized());
    assert!(VmType::Heap.is_zero_initialized());
    assert!(VmType::Stack.is_zero_initialized());
    assert!(!VmType::File.is_zero_initialized());
    assert!(!VmType::Device.is_zero_initialized());
}

#[test]
fn test_vm_type_is_demand_paged() {
    assert!(VmType::Anonymous.is_demand_paged());
    assert!(VmType::Heap.is_demand_paged());
    assert!(VmType::Stack.is_demand_paged());
    assert!(!VmType::File.is_demand_paged());
    assert!(!VmType::Device.is_demand_paged());
}

// ============================================================================
// VM AREA TESTS
// ============================================================================

#[test]
fn test_vm_area_creation() {
    let area = VmArea::new(
        VirtAddr::new(0x1000),
        0x2000,
        VmProtection::ReadWrite,
        VmType::Heap,
    );

    assert_eq!(area.start.as_u64(), 0x1000);
    assert_eq!(area.size, 0x2000);
    assert_eq!(area.protection, VmProtection::ReadWrite);
    assert_eq!(area.vm_type, VmType::Heap);
    assert_eq!(area.flags, 0);
    assert_eq!(area.access_count, 0);
    assert_eq!(area.fault_count, 0);
}

#[test]
fn test_vm_area_end() {
    let area = VmArea::new(
        VirtAddr::new(0x1000),
        0x2000,
        VmProtection::Read,
        VmType::Code,
    );

    assert_eq!(area.end().as_u64(), 0x3000);
}

#[test]
fn test_vm_area_contains() {
    let area = VmArea::new(
        VirtAddr::new(0x1000),
        0x2000,
        VmProtection::Read,
        VmType::Code,
    );

    assert!(area.contains(VirtAddr::new(0x1000)));
    assert!(area.contains(VirtAddr::new(0x2000)));
    assert!(area.contains(VirtAddr::new(0x2FFF)));
    assert!(!area.contains(VirtAddr::new(0x0FFF)));
    assert!(!area.contains(VirtAddr::new(0x3000)));
}

#[test]
fn test_vm_area_overlaps() {
    let area1 = VmArea::new(
        VirtAddr::new(0x1000),
        0x2000,
        VmProtection::Read,
        VmType::Code,
    );
    let area2 = VmArea::new(
        VirtAddr::new(0x2000),
        0x2000,
        VmProtection::Read,
        VmType::Code,
    );
    let area3 = VmArea::new(
        VirtAddr::new(0x5000),
        0x1000,
        VmProtection::Read,
        VmType::Code,
    );

    assert!(area1.overlaps(&area2));
    assert!(area2.overlaps(&area1));
    assert!(!area1.overlaps(&area3));
    assert!(!area3.overlaps(&area1));
}

#[test]
fn test_vm_area_can_merge() {
    let area1 = VmArea::new(
        VirtAddr::new(0x1000),
        0x1000,
        VmProtection::Read,
        VmType::Code,
    );
    let area2 = VmArea::new(
        VirtAddr::new(0x2000),
        0x1000,
        VmProtection::Read,
        VmType::Code,
    );
    let area3 = VmArea::new(
        VirtAddr::new(0x2000),
        0x1000,
        VmProtection::ReadWrite,
        VmType::Code,
    );

    assert!(area1.can_merge(&area2));
    assert!(!area1.can_merge(&area3)); // Different protection
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_vm_error_as_str() {
    assert_eq!(
        VmError::NotInitialized.as_str(),
        "Virtual memory manager not initialized"
    );
    assert_eq!(
        VmError::AddressSpaceNotFound.as_str(),
        "Address space not found"
    );
    assert_eq!(VmError::VmAreaNotFound.as_str(), "VM area not found");
    assert_eq!(
        VmError::Overlapping.as_str(),
        "VM area overlaps with existing area"
    );
    assert_eq!(
        VmError::WriteProtectionFault.as_str(),
        "Write to read-only memory"
    );
    assert_eq!(
        VmError::ExecuteProtectionFault.as_str(),
        "Execute on non-executable memory"
    );
}

#[test]
fn test_vm_error_is_protection_fault() {
    assert!(VmError::WriteProtectionFault.is_protection_fault());
    assert!(VmError::ExecuteProtectionFault.is_protection_fault());
    assert!(!VmError::NotInitialized.is_protection_fault());
    assert!(!VmError::VmAreaNotFound.is_protection_fault());
}

#[test]
fn test_vm_error_is_recoverable() {
    assert!(VmError::NotInitialized.is_recoverable());
    assert!(VmError::Overlapping.is_recoverable());
    assert!(VmError::VmAreaNotFound.is_recoverable());
    assert!(!VmError::WriteProtectionFault.is_recoverable());
}

#[test]
fn test_vm_error_is_fatal() {
    assert!(VmError::WriteProtectionFault.is_fatal());
    assert!(VmError::ExecuteProtectionFault.is_fatal());
    assert!(!VmError::NotInitialized.is_fatal());
    assert!(!VmError::Overlapping.is_fatal());
}

#[test]
fn test_vm_error_display() {
    let error = VmError::VmAreaNotFound;
    let msg = format!("{}", error);
    assert_eq!(msg, "VM area not found");
}

// ============================================================================
// STATS TESTS
// ============================================================================

#[test]
fn test_vmem_stats_new() {
    let stats = VirtualMemoryStatistics::new();
    assert_eq!(stats.total_vm_areas(), 0);
    assert_eq!(stats.total_virtual_memory(), 0);
    assert_eq!(stats.heap_usage(), 0);
    assert_eq!(stats.stack_usage(), 0);
    assert_eq!(stats.mmap_usage(), 0);
    assert_eq!(stats.page_faults(), 0);
    assert_eq!(stats.protection_faults(), 0);
}

#[test]
fn test_vmem_stats_record_vm_area() {
    let stats = VirtualMemoryStatistics::new();

    stats.record_vm_area(0x1000, VmType::Heap);
    assert_eq!(stats.total_vm_areas(), 1);
    assert_eq!(stats.total_virtual_memory(), 0x1000);
    assert_eq!(stats.heap_usage(), 0x1000);

    stats.record_vm_area(0x2000, VmType::Stack);
    assert_eq!(stats.total_vm_areas(), 2);
    assert_eq!(stats.total_virtual_memory(), 0x3000);
    assert_eq!(stats.stack_usage(), 0x2000);
}

#[test]
fn test_vmem_stats_record_vm_area_removal() {
    let stats = VirtualMemoryStatistics::new();

    stats.record_vm_area(0x2000, VmType::Heap);
    stats.record_vm_area_removal(0x1000, VmType::Heap);

    assert_eq!(stats.heap_usage(), 0x1000);
}

#[test]
fn test_vmem_stats_record_faults() {
    let stats = VirtualMemoryStatistics::new();

    stats.record_page_fault();
    assert_eq!(stats.page_faults(), 1);

    stats.record_protection_fault();
    assert_eq!(stats.protection_faults(), 1);
}

#[test]
fn test_vmem_stats_record_tlb_shootdowns() {
    let stats = VirtualMemoryStatistics::new();

    stats.record_tlb_shootdowns(5);
    assert_eq!(stats.tlb_shootdowns(), 5);

    stats.record_tlb_shootdowns(3);
    assert_eq!(stats.tlb_shootdowns(), 8);
}

// ============================================================================
// VM STATS TESTS
// ============================================================================

#[test]
fn test_vm_stats_structure() {
    let stats = VmStats {
        total_vm_areas: 10,
        address_spaces: 2,
        total_virtual_memory: 0x100000,
        heap_usage: 0x40000,
        stack_usage: 0x20000,
        mmap_usage: 0x30000,
        page_faults: 100,
        protection_faults: 5,
        swap_operations: 10,
        tlb_shootdowns: 50,
    };

    assert_eq!(stats.total_vm_areas, 10);
    assert_eq!(stats.address_spaces, 2);
    assert_eq!(stats.total_virtual_memory, 0x100000);
    assert_eq!(stats.heap_usage, 0x40000);
    assert_eq!(stats.stack_usage, 0x20000);
    assert_eq!(stats.mmap_usage, 0x30000);
    assert_eq!(stats.page_faults, 100);
    assert_eq!(stats.protection_faults, 5);
    assert_eq!(stats.swap_operations, 10);
    assert_eq!(stats.tlb_shootdowns, 50);
}
