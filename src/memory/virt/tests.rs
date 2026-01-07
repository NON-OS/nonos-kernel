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
fn test_page_sizes() {
    assert_eq!(PAGE_SIZE_4K, 4096);
    assert_eq!(PAGE_SIZE_2M, 2 * 1024 * 1024);
    assert_eq!(PAGE_SIZE_1G, 1024 * 1024 * 1024);
    assert_eq!(PAGE_SIZE, PAGE_SIZE_4K);
}

#[test]
fn test_page_table_constants() {
    assert_eq!(PAGE_TABLE_ENTRIES, 512);
    assert_eq!(PTE_SIZE, 8);
    assert_eq!(PAGE_TABLE_INDEX_MASK, 0x1FF);
}

#[test]
fn test_index_shifts() {
    assert_eq!(L4_INDEX_SHIFT, 39);
    assert_eq!(L3_INDEX_SHIFT, 30);
    assert_eq!(L2_INDEX_SHIFT, 21);
    assert_eq!(L1_INDEX_SHIFT, 12);
}

#[test]
fn test_pte_flags() {
    assert_eq!(PTE_PRESENT, 1 << 0);
    assert_eq!(PTE_WRITABLE, 1 << 1);
    assert_eq!(PTE_USER, 1 << 2);
    assert_eq!(PTE_WRITE_THROUGH, 1 << 3);
    assert_eq!(PTE_CACHE_DISABLE, 1 << 4);
    assert_eq!(PTE_ACCESSED, 1 << 5);
    assert_eq!(PTE_DIRTY, 1 << 6);
    assert_eq!(PTE_HUGE_PAGE, 1 << 7);
    assert_eq!(PTE_GLOBAL, 1 << 8);
    assert_eq!(PTE_NO_EXECUTE, 1u64 << 63);
}

#[test]
fn test_page_fault_codes() {
    assert_eq!(PF_PRESENT, 1 << 0);
    assert_eq!(PF_WRITE, 1 << 1);
    assert_eq!(PF_USER, 1 << 2);
}

// ============================================================================
// INDEX EXTRACTION TESTS
// ============================================================================

#[test]
fn test_l4_index() {
    // Address with L4 index = 256
    let addr = 256u64 << 39;
    assert_eq!(l4_index(addr), 256);

    // Address with L4 index = 0
    assert_eq!(l4_index(0), 0);

    // Address with L4 index = 511
    let addr = 511u64 << 39;
    assert_eq!(l4_index(addr), 511);
}

#[test]
fn test_l3_index() {
    let addr = 100u64 << 30;
    assert_eq!(l3_index(addr), 100);
}

#[test]
fn test_l2_index() {
    let addr = 200u64 << 21;
    assert_eq!(l2_index(addr), 200);
}

#[test]
fn test_l1_index() {
    let addr = 300u64 << 12;
    assert_eq!(l1_index(addr), 300);
}

#[test]
fn test_pte_is_present() {
    assert!(pte_is_present(PTE_PRESENT));
    assert!(pte_is_present(PTE_PRESENT | PTE_WRITABLE));
    assert!(!pte_is_present(0));
    assert!(!pte_is_present(PTE_WRITABLE)); // Writable but not present
}

#[test]
fn test_pte_address() {
    let pte = 0x1234_5000 | PTE_PRESENT | PTE_WRITABLE;
    assert_eq!(pte_address(pte), 0x1234_5000);

    // Address with NX bit set
    let pte = 0x1234_5000 | PTE_PRESENT | PTE_NO_EXECUTE;
    assert_eq!(pte_address(pte), 0x1234_5000);
}

// ============================================================================
// VM FLAGS TESTS
// ============================================================================

#[test]
fn test_vm_flags_values() {
    assert_eq!(VmFlags::None.bits(), 0);
    assert_eq!(VmFlags::Present.bits(), PTE_PRESENT);
    assert_eq!(VmFlags::Write.bits(), PTE_WRITABLE);
    assert_eq!(VmFlags::User.bits(), PTE_USER);
    assert_eq!(VmFlags::NoExecute.bits(), PTE_NO_EXECUTE);
}

#[test]
fn test_vm_flags_contains() {
    let flags = VmFlags::Present;
    assert!(flags.contains(VmFlags::Present));
    assert!(!flags.contains(VmFlags::Write));
}

#[test]
fn test_vm_flags_bitor() {
    let flags = VmFlags::Present | VmFlags::Write;
    assert!(flags.contains(VmFlags::Present));
    assert!(flags.contains(VmFlags::Write));
    assert!(!flags.contains(VmFlags::User));
}

#[test]
fn test_vm_flags_bitand() {
    let flags = VmFlags::Present | VmFlags::Write | VmFlags::User;
    let mask = VmFlags::Present | VmFlags::Write;
    let result = flags & mask;
    assert!(result.contains(VmFlags::Present));
    assert!(result.contains(VmFlags::Write));
}

// ============================================================================
// PAGE SIZE TESTS
// ============================================================================

#[test]
fn test_page_size_bytes() {
    assert_eq!(PageSize::Size4K.bytes(), 4096);
    assert_eq!(PageSize::Size2M.bytes(), 2 * 1024 * 1024);
    assert_eq!(PageSize::Size1G.bytes(), 1024 * 1024 * 1024);
}

#[test]
fn test_page_size_mask() {
    assert_eq!(PageSize::Size4K.mask(), 0xFFF);
    assert_eq!(PageSize::Size2M.mask(), 0x1F_FFFF);
}

#[test]
fn test_page_size_alignment() {
    assert!(PageSize::Size4K.is_aligned(0x1000));
    assert!(PageSize::Size4K.is_aligned(0x2000));
    assert!(!PageSize::Size4K.is_aligned(0x1001));

    assert!(PageSize::Size2M.is_aligned(0x200000));
    assert!(!PageSize::Size2M.is_aligned(0x100000));
}

// ============================================================================
// MAPPED RANGE TESTS
// ============================================================================

#[test]
fn test_mapped_range_creation() {
    use x86_64::{PhysAddr, VirtAddr};

    let range = MappedRange::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        VmFlags::Present,
        PageSize::Size4K,
    );

    assert_eq!(range.start_va.as_u64(), 0x1000);
    assert_eq!(range.start_pa.as_u64(), 0x2000);
    assert_eq!(range.size, 4096);
}

#[test]
fn test_mapped_range_contains() {
    use x86_64::{PhysAddr, VirtAddr};

    let range = MappedRange::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        VmFlags::Present,
        PageSize::Size4K,
    );

    assert!(range.contains(VirtAddr::new(0x1000)));
    assert!(range.contains(VirtAddr::new(0x1500)));
    assert!(range.contains(VirtAddr::new(0x1FFF)));
    assert!(!range.contains(VirtAddr::new(0x2000)));
    assert!(!range.contains(VirtAddr::new(0x0FFF)));
}

#[test]
fn test_mapped_range_translate() {
    use x86_64::{PhysAddr, VirtAddr};

    let range = MappedRange::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        VmFlags::Present,
        PageSize::Size4K,
    );

    assert_eq!(
        range.translate(VirtAddr::new(0x1000)),
        Some(PhysAddr::new(0x2000))
    );
    assert_eq!(
        range.translate(VirtAddr::new(0x1100)),
        Some(PhysAddr::new(0x2100))
    );
    assert_eq!(range.translate(VirtAddr::new(0x2000)), None);
}

#[test]
fn test_mapped_range_end_va() {
    use x86_64::{PhysAddr, VirtAddr};

    let range = MappedRange::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        8192,
        VmFlags::Present,
        PageSize::Size4K,
    );

    assert_eq!(range.end_va().as_u64(), 0x3000);
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
    assert_eq!(VmError::OutOfMemory.as_str(), "Out of physical memory for page tables");
    assert_eq!(VmError::WXViolation.as_str(), "Cannot map memory as both writable and executable");
}

#[test]
fn test_vm_error_is_fatal() {
    assert!(VmError::OutOfMemory.is_fatal());
    assert!(VmError::PageTableError.is_fatal());
    assert!(VmError::FrameAllocationFailed.is_fatal());
    assert!(!VmError::AddressNotMapped.is_fatal());
}

#[test]
fn test_vm_error_is_security_violation() {
    assert!(VmError::PermissionViolation.is_security_violation());
    assert!(VmError::WXViolation.is_security_violation());
    assert!(!VmError::NotInitialized.is_security_violation());
}

#[test]
fn test_vm_error_display() {
    let error = VmError::InvalidAlignment;
    let msg = format!("{}", error);
    assert_eq!(msg, "Invalid alignment for mapping");
}

// ============================================================================
// STATS TESTS
// ============================================================================

#[test]
fn test_vm_stats_new() {
    let stats = VmStats::new();
    assert_eq!(stats.mapped_pages(), 0);
    assert_eq!(stats.mapped_memory(), 0);
    assert_eq!(stats.page_faults(), 0);
    assert_eq!(stats.tlb_flushes(), 0);
    assert_eq!(stats.wx_violations(), 0);
}

#[test]
fn test_vm_stats_record_mapping() {
    let stats = VmStats::new();
    stats.record_mapping(4096);
    assert_eq!(stats.mapped_pages(), 1);
    assert_eq!(stats.mapped_memory(), 4096);

    stats.record_mapping(8192);
    assert_eq!(stats.mapped_pages(), 3);
    assert_eq!(stats.mapped_memory(), 4096 + 8192);
}

#[test]
fn test_vm_stats_record_unmapping() {
    let stats = VmStats::new();
    stats.record_mapping(8192);
    stats.record_unmapping(4096);
    assert_eq!(stats.mapped_pages(), 1);
    assert_eq!(stats.mapped_memory(), 4096);
}

#[test]
fn test_vm_stats_counters() {
    let stats = VmStats::new();
    stats.record_page_fault();
    stats.record_page_fault();
    stats.record_tlb_flush();
    stats.record_wx_violation();

    assert_eq!(stats.page_faults(), 2);
    assert_eq!(stats.tlb_flushes(), 1);
    assert_eq!(stats.wx_violations(), 1);
}

#[test]
fn test_vm_stats_snapshot() {
    let stats = VmStats::new();
    stats.record_mapping(4096);
    stats.record_page_fault();

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.mapped_pages, 1);
    assert_eq!(snapshot.mapped_memory, 4096);
    assert_eq!(snapshot.page_faults, 1);
}

// ============================================================================
// STATS SNAPSHOT TESTS
// ============================================================================

#[test]
fn test_vm_stats_snapshot_new() {
    let snapshot = VmStatsSnapshot::new();
    assert_eq!(snapshot.mapped_pages, 0);
    assert_eq!(snapshot.mapped_memory, 0);
    assert_eq!(snapshot.page_faults, 0);
    assert_eq!(snapshot.tlb_flushes, 0);
    assert_eq!(snapshot.wx_violations, 0);
}

// ============================================================================
// MANAGER TESTS
// ============================================================================

#[test]
fn test_manager_new() {
    let manager = VirtualMemoryManager::new();
    assert!(!manager.is_initialized());
}

// ============================================================================
// BUILD FLAGS TESTS
// ============================================================================

#[test]
fn test_build_flags_readable() {
    let flags = build_flags(false, false, false);
    assert!(flags.contains(VmFlags::Present));
    assert!(flags.contains(VmFlags::NoExecute));
    assert!(!flags.contains(VmFlags::Write));
    assert!(!flags.contains(VmFlags::User));
}

#[test]
fn test_build_flags_writable() {
    let flags = build_flags(true, false, false);
    assert!(flags.contains(VmFlags::Present));
    assert!(flags.contains(VmFlags::Write));
    assert!(flags.contains(VmFlags::NoExecute));
}

#[test]
fn test_build_flags_user() {
    let flags = build_flags(false, true, false);
    assert!(flags.contains(VmFlags::Present));
    assert!(flags.contains(VmFlags::User));
}

#[test]
fn test_build_flags_executable() {
    let flags = build_flags(false, false, true);
    assert!(flags.contains(VmFlags::Present));
    assert!(!flags.contains(VmFlags::NoExecute));
}
