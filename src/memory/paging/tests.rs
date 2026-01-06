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
fn test_page_sizes() {
    assert_eq!(PAGE_SIZE_4K, 4096);
    assert_eq!(PAGE_SIZE_2M, 2 * 1024 * 1024);
    assert_eq!(PAGE_SIZE_1G, 1024 * 1024 * 1024);
}

#[test]
fn test_page_fault_codes() {
    assert_eq!(PF_PRESENT, 1 << 0);
    assert_eq!(PF_WRITE, 1 << 1);
    assert_eq!(PF_USER, 1 << 2);
    assert_eq!(PF_RESERVED, 1 << 3);
    assert_eq!(PF_INSTRUCTION, 1 << 4);
}

#[test]
fn test_permission_bits() {
    assert_eq!(PERM_READ, 1 << 0);
    assert_eq!(PERM_WRITE, 1 << 1);
    assert_eq!(PERM_EXECUTE, 1 << 2);
    assert_eq!(PERM_USER, 1 << 3);
    assert_eq!(PERM_GLOBAL, 1 << 4);
    assert_eq!(PERM_NO_CACHE, 1 << 5);
}

// ============================================================================
// INDEX EXTRACTION TESTS
// ============================================================================

#[test]
fn test_pml4_index() {
    assert_eq!(pml4_index(0), 0);
    assert_eq!(pml4_index(256u64 << 39), 256);
    assert_eq!(pml4_index(511u64 << 39), 511);
}

#[test]
fn test_pdpt_index() {
    assert_eq!(pdpt_index(0), 0);
    assert_eq!(pdpt_index(100u64 << 30), 100);
    assert_eq!(pdpt_index(511u64 << 30), 511);
}

#[test]
fn test_pd_index() {
    assert_eq!(pd_index(0), 0);
    assert_eq!(pd_index(200u64 << 21), 200);
    assert_eq!(pd_index(511u64 << 21), 511);
}

#[test]
fn test_pt_index() {
    assert_eq!(pt_index(0), 0);
    assert_eq!(pt_index(300u64 << 12), 300);
    assert_eq!(pt_index(511u64 << 12), 511);
}

#[test]
fn test_page_offset() {
    assert_eq!(page_offset(0), 0);
    assert_eq!(page_offset(0x123), 0x123);
    assert_eq!(page_offset(0xFFF), 0xFFF);
    assert_eq!(page_offset(0x1000), 0);
    assert_eq!(page_offset(0x1234), 0x234);
}

// ============================================================================
// PTE HELPER TESTS
// ============================================================================

#[test]
fn test_pte_is_present() {
    assert!(pte_is_present(PTE_PRESENT));
    assert!(pte_is_present(PTE_PRESENT | PTE_WRITABLE));
    assert!(!pte_is_present(0));
    assert!(!pte_is_present(PTE_WRITABLE));
}

#[test]
fn test_pte_is_huge() {
    assert!(pte_is_huge(PTE_HUGE_PAGE));
    assert!(pte_is_huge(PTE_PRESENT | PTE_HUGE_PAGE));
    assert!(!pte_is_huge(PTE_PRESENT));
    assert!(!pte_is_huge(0));
}

#[test]
fn test_pte_address() {
    let pte = 0x1234_5000 | PTE_PRESENT | PTE_WRITABLE;
    assert_eq!(pte_address(pte), 0x1234_5000);

    let pte_with_nx = 0x1234_5000 | PTE_PRESENT | PTE_NO_EXECUTE;
    assert_eq!(pte_address(pte_with_nx), 0x1234_5000);
}

// ============================================================================
// ALIGNMENT TESTS
// ============================================================================

#[test]
fn test_page_align_down() {
    assert_eq!(page_align_down(0), 0);
    assert_eq!(page_align_down(0x1000), 0x1000);
    assert_eq!(page_align_down(0x1001), 0x1000);
    assert_eq!(page_align_down(0x1FFF), 0x1000);
    assert_eq!(page_align_down(0x2000), 0x2000);
}

#[test]
fn test_page_align_up() {
    assert_eq!(page_align_up(0), 0);
    assert_eq!(page_align_up(0x1000), 0x1000);
    assert_eq!(page_align_up(0x1001), 0x2000);
    assert_eq!(page_align_up(0x1FFF), 0x2000);
    assert_eq!(page_align_up(0x2000), 0x2000);
}

#[test]
fn test_pages_needed() {
    assert_eq!(pages_needed(0), 0);
    assert_eq!(pages_needed(1), 1);
    assert_eq!(pages_needed(4096), 1);
    assert_eq!(pages_needed(4097), 2);
    assert_eq!(pages_needed(8192), 2);
}

// ============================================================================
// PAGE PERMISSIONS TESTS
// ============================================================================

#[test]
fn test_permissions_contains() {
    let rw = PagePermissions::READ | PagePermissions::WRITE;
    assert!(rw.contains(PagePermissions::READ));
    assert!(rw.contains(PagePermissions::WRITE));
    assert!(!rw.contains(PagePermissions::EXECUTE));
}

#[test]
fn test_permissions_union() {
    let r = PagePermissions::READ;
    let w = PagePermissions::WRITE;
    let rw = r.union(w);
    assert!(rw.contains(PagePermissions::READ));
    assert!(rw.contains(PagePermissions::WRITE));
}

#[test]
fn test_permissions_remove() {
    let rwx = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::EXECUTE;
    let rw = rwx.remove(PagePermissions::EXECUTE);
    assert!(rw.contains(PagePermissions::READ));
    assert!(rw.contains(PagePermissions::WRITE));
    assert!(!rw.contains(PagePermissions::EXECUTE));
}

#[test]
fn test_permissions_wx_violation() {
    let rw = PagePermissions::READ | PagePermissions::WRITE;
    assert!(!rw.is_wx_violation());

    let rx = PagePermissions::READ | PagePermissions::EXECUTE;
    assert!(!rx.is_wx_violation());

    let wx = PagePermissions::WRITE | PagePermissions::EXECUTE;
    assert!(wx.is_wx_violation());

    let rwx = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::EXECUTE;
    assert!(rwx.is_wx_violation());
}

#[test]
fn test_permissions_to_pte_flags() {
    let ro = PagePermissions::READ;
    let flags = ro.to_pte_flags();
    assert!(flags & PTE_PRESENT != 0);
    assert!(flags & PTE_WRITABLE == 0);
    assert!(flags & PTE_NO_EXECUTE != 0);

    let rw = PagePermissions::READ | PagePermissions::WRITE;
    let flags = rw.to_pte_flags();
    assert!(flags & PTE_PRESENT != 0);
    assert!(flags & PTE_WRITABLE != 0);
    assert!(flags & PTE_NO_EXECUTE != 0);

    let rx = PagePermissions::READ | PagePermissions::EXECUTE;
    let flags = rx.to_pte_flags();
    assert!(flags & PTE_PRESENT != 0);
    assert!(flags & PTE_WRITABLE == 0);
    assert!(flags & PTE_NO_EXECUTE == 0);
}

#[test]
fn test_permissions_presets() {
    let kernel_ro = PagePermissions::kernel_ro();
    assert!(kernel_ro.contains(PagePermissions::READ));
    assert!(!kernel_ro.contains(PagePermissions::WRITE));
    assert!(!kernel_ro.contains(PagePermissions::USER));

    let kernel_rw = PagePermissions::kernel_rw();
    assert!(kernel_rw.contains(PagePermissions::READ));
    assert!(kernel_rw.contains(PagePermissions::WRITE));
    assert!(!kernel_rw.contains(PagePermissions::USER));

    let user_ro = PagePermissions::user_ro();
    assert!(user_ro.contains(PagePermissions::READ));
    assert!(!user_ro.contains(PagePermissions::WRITE));
    assert!(user_ro.contains(PagePermissions::USER));

    let device = PagePermissions::device();
    assert!(device.contains(PagePermissions::READ));
    assert!(device.contains(PagePermissions::WRITE));
    assert!(device.contains(PagePermissions::NO_CACHE));
    assert!(device.contains(PagePermissions::DEVICE));
}

// ============================================================================
// PAGE SIZE TESTS
// ============================================================================

#[test]
fn test_page_size_bytes() {
    assert_eq!(PageSize::Size4KiB.bytes(), 4096);
    assert_eq!(PageSize::Size2MiB.bytes(), 2 * 1024 * 1024);
    assert_eq!(PageSize::Size1GiB.bytes(), 1024 * 1024 * 1024);
}

#[test]
fn test_page_size_align_mask() {
    assert_eq!(PageSize::Size4KiB.align_mask(), 0xFFF);
    assert_eq!(PageSize::Size2MiB.align_mask(), 0x1F_FFFF);
    assert_eq!(PageSize::Size1GiB.align_mask(), 0x3FFF_FFFF);
}

#[test]
fn test_page_size_is_aligned() {
    assert!(PageSize::Size4KiB.is_aligned(0));
    assert!(PageSize::Size4KiB.is_aligned(0x1000));
    assert!(!PageSize::Size4KiB.is_aligned(0x1001));

    assert!(PageSize::Size2MiB.is_aligned(0));
    assert!(PageSize::Size2MiB.is_aligned(0x20_0000));
    assert!(!PageSize::Size2MiB.is_aligned(0x1000));
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_paging_error_as_str() {
    assert_eq!(
        PagingError::NotInitialized.as_str(),
        "Paging manager not initialized"
    );
    assert_eq!(
        PagingError::WXViolation.as_str(),
        "W^X violation: RW+X not allowed"
    );
    assert_eq!(PagingError::PageNotMapped.as_str(), "Page not mapped");
}

#[test]
fn test_paging_error_is_fatal() {
    assert!(PagingError::NoActivePageTable.is_fatal());
    assert!(PagingError::FrameAllocationFailed.is_fatal());
    assert!(PagingError::KernelSpaceViolation.is_fatal());
    assert!(!PagingError::PageNotMapped.is_fatal());
}

#[test]
fn test_paging_error_is_security_violation() {
    assert!(PagingError::WXViolation.is_security_violation());
    assert!(PagingError::PermissionDenied.is_security_violation());
    assert!(PagingError::KernelSpaceViolation.is_security_violation());
    assert!(!PagingError::NotInitialized.is_security_violation());
}

#[test]
fn test_paging_error_is_recoverable() {
    assert!(PagingError::PageNotMapped.is_recoverable());
    assert!(PagingError::Pml4NotPresent.is_recoverable());
    assert!(PagingError::PdptNotPresent.is_recoverable());
    assert!(!PagingError::WXViolation.is_recoverable());
}

#[test]
fn test_paging_error_display() {
    let error = PagingError::PageNotMapped;
    let msg = format!("{}", error);
    assert_eq!(msg, "Page not mapped");
}

#[test]
fn test_paging_error_from_str() {
    assert_eq!(
        PagingError::from("Paging manager not initialized"),
        PagingError::NotInitialized
    );
    assert_eq!(
        PagingError::from("L4 entry not present"),
        PagingError::Pml4NotPresent
    );
    assert_eq!(
        PagingError::from("Page not mapped"),
        PagingError::PageNotMapped
    );
}

// ============================================================================
// PAGE FAULT INFO TESTS
// ============================================================================

#[test]
fn test_page_fault_info_creation() {
    let info = PageFaultInfo::from_fault(0x1000, PF_WRITE | PF_PRESENT);
    assert_eq!(info.address, 0x1000);
    assert!(info.is_write);
    assert!(info.page_was_present);
    assert!(!info.is_user);
}

#[test]
fn test_page_fault_info_cow() {
    let cow_fault = PageFaultInfo::from_fault(0x1000, PF_WRITE | PF_PRESENT);
    assert!(cow_fault.is_cow_fault());
    assert!(!cow_fault.is_demand_fault());

    let demand_fault = PageFaultInfo::from_fault(0x1000, 0);
    assert!(!demand_fault.is_cow_fault());
    assert!(demand_fault.is_demand_fault());
}

// ============================================================================
// PAGE MAPPING TESTS
// ============================================================================

#[test]
fn test_page_mapping_creation() {
    use x86_64::{PhysAddr, VirtAddr};

    let mapping = PageMapping::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        PageSize::Size4KiB,
        PagePermissions::kernel_rw(),
    );

    assert_eq!(mapping.virtual_addr.as_u64(), 0x1000);
    assert_eq!(mapping.physical_addr.as_u64(), 0x2000);
    assert!(matches!(mapping.size, PageSize::Size4KiB));
    assert!(mapping.is_kernel());
    assert!(!mapping.is_user());
    assert!(!mapping.is_huge());
    assert_eq!(mapping.reference_count, 1);
}

#[test]
fn test_page_mapping_kernel() {
    use x86_64::{PhysAddr, VirtAddr};

    let mapping = PageMapping::kernel(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        PagePermissions::kernel_ro(),
    );

    assert!(mapping.is_kernel());
    assert_eq!(mapping.process_id, None);
}

#[test]
fn test_page_mapping_user() {
    use x86_64::{PhysAddr, VirtAddr};

    let mapping = PageMapping::user(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        PagePermissions::user_rw(),
        42,
    );

    assert!(mapping.is_user());
    assert_eq!(mapping.process_id, Some(42));
}

#[test]
fn test_page_mapping_huge() {
    use x86_64::{PhysAddr, VirtAddr};

    let small = PageMapping::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        PageSize::Size4KiB,
        PagePermissions::kernel_rw(),
    );
    assert!(!small.is_huge());

    let huge_2m = PageMapping::new(
        VirtAddr::new(0x20_0000),
        PhysAddr::new(0x40_0000),
        PageSize::Size2MiB,
        PagePermissions::kernel_rw(),
    );
    assert!(huge_2m.is_huge());

    let huge_1g = PageMapping::new(
        VirtAddr::new(0x4000_0000),
        PhysAddr::new(0x8000_0000),
        PageSize::Size1GiB,
        PagePermissions::kernel_rw(),
    );
    assert!(huge_1g.is_huge());
}

// ============================================================================
// PAGING STATS TESTS
// ============================================================================

#[test]
fn test_paging_stats_default() {
    let stats = PagingStats::default();
    assert_eq!(stats.total_mappings, 0);
    assert_eq!(stats.page_faults, 0);
    assert_eq!(stats.tlb_flushes, 0);
    assert_eq!(stats.huge_pages, 0);
}
