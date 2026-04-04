use crate::memory::paging::{
    PageSize, PagePermissions, PageMapping, PageFaultInfo, PagingError,
    PTE_PRESENT, PTE_WRITABLE, PTE_USER, PTE_WRITE_THROUGH, PTE_CACHE_DISABLE,
    PTE_ACCESSED, PTE_DIRTY, PTE_HUGE_PAGE, PTE_GLOBAL, PTE_NO_EXECUTE,
    PTE_ADDR_MASK, PTE_FLAGS_MASK, PTE_TABLE_FLAGS, PTE_KERNEL_TABLE,
    PAGE_TABLE_ENTRIES, PML4_SHIFT, PDPT_SHIFT, PD_SHIFT, PT_SHIFT,
    INDEX_MASK, PAGE_OFFSET_MASK,
    PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G,
    PERM_READ, PERM_WRITE, PERM_EXECUTE, PERM_USER, PERM_GLOBAL,
    PERM_NO_CACHE, PERM_WRITE_THROUGH, PERM_COW, PERM_DEMAND,
    PERM_ZERO_FILL, PERM_SHARED, PERM_LOCKED, PERM_DEVICE,
    pml4_index, pdpt_index, pd_index, pt_index, page_offset,
    pte_is_present, pte_is_huge, pte_address,
    page_align_down, page_align_up, pages_needed,
    set_aslr_enabled, is_aslr_enabled,
};
use x86_64::{PhysAddr, VirtAddr};

#[test]
fn test_page_size_4kib_bytes() {
    assert_eq!(PageSize::Size4KiB.bytes(), PAGE_SIZE_4K);
}

#[test]
fn test_page_size_2mib_bytes() {
    assert_eq!(PageSize::Size2MiB.bytes(), PAGE_SIZE_2M);
}

#[test]
fn test_page_size_1gib_bytes() {
    assert_eq!(PageSize::Size1GiB.bytes(), PAGE_SIZE_1G);
}

#[test]
fn test_page_size_4kib_align_mask() {
    assert_eq!(PageSize::Size4KiB.align_mask(), 0xFFF);
}

#[test]
fn test_page_size_2mib_align_mask() {
    assert_eq!(PageSize::Size2MiB.align_mask(), 0x1F_FFFF);
}

#[test]
fn test_page_size_1gib_align_mask() {
    assert_eq!(PageSize::Size1GiB.align_mask(), 0x3FFF_FFFF);
}

#[test]
fn test_page_size_4kib_is_aligned() {
    assert!(PageSize::Size4KiB.is_aligned(0x1000));
    assert!(!PageSize::Size4KiB.is_aligned(0x1001));
}

#[test]
fn test_page_size_2mib_is_aligned() {
    assert!(PageSize::Size2MiB.is_aligned(0x200000));
    assert!(!PageSize::Size2MiB.is_aligned(0x200001));
}

#[test]
fn test_page_size_1gib_is_aligned() {
    assert!(PageSize::Size1GiB.is_aligned(0x40000000));
    assert!(!PageSize::Size1GiB.is_aligned(0x40000001));
}

#[test]
fn test_page_size_default() {
    assert_eq!(PageSize::default(), PageSize::Size4KiB);
}

#[test]
fn test_page_size_equality() {
    assert_eq!(PageSize::Size4KiB, PageSize::Size4KiB);
    assert_ne!(PageSize::Size4KiB, PageSize::Size2MiB);
}

#[test]
fn test_page_permissions_empty() {
    let p = PagePermissions::empty();
    assert_eq!(p.bits(), 0);
}

#[test]
fn test_page_permissions_from_bits() {
    let p = PagePermissions::from_bits(PERM_READ | PERM_WRITE);
    assert_eq!(p.bits(), PERM_READ | PERM_WRITE);
}

#[test]
fn test_page_permissions_contains_read() {
    let p = PagePermissions::READ;
    assert!(p.contains(PagePermissions::READ));
    assert!(!p.contains(PagePermissions::WRITE));
}

#[test]
fn test_page_permissions_union() {
    let p = PagePermissions::READ.union(PagePermissions::WRITE);
    assert!(p.contains(PagePermissions::READ));
    assert!(p.contains(PagePermissions::WRITE));
}

#[test]
fn test_page_permissions_remove() {
    let p = PagePermissions::READ.union(PagePermissions::WRITE);
    let removed = p.remove(PagePermissions::WRITE);
    assert!(removed.contains(PagePermissions::READ));
    assert!(!removed.contains(PagePermissions::WRITE));
}

#[test]
fn test_page_permissions_insert() {
    let p = PagePermissions::READ.insert(PagePermissions::EXECUTE);
    assert!(p.contains(PagePermissions::READ));
    assert!(p.contains(PagePermissions::EXECUTE));
}

#[test]
fn test_page_permissions_wx_violation() {
    let wx = PagePermissions::WRITE.union(PagePermissions::EXECUTE);
    assert!(wx.is_wx_violation());
}

#[test]
fn test_page_permissions_no_wx_violation() {
    let rw = PagePermissions::READ.union(PagePermissions::WRITE);
    assert!(!rw.is_wx_violation());
}

#[test]
fn test_page_permissions_bitor() {
    let p = PagePermissions::READ | PagePermissions::WRITE;
    assert!(p.contains(PagePermissions::READ));
    assert!(p.contains(PagePermissions::WRITE));
}

#[test]
fn test_page_permissions_bitor_assign() {
    let mut p = PagePermissions::READ;
    p |= PagePermissions::EXECUTE;
    assert!(p.contains(PagePermissions::READ));
    assert!(p.contains(PagePermissions::EXECUTE));
}

#[test]
fn test_page_permissions_bitand() {
    let p1 = PagePermissions::READ | PagePermissions::WRITE;
    let p2 = PagePermissions::READ | PagePermissions::EXECUTE;
    let result = p1 & p2;
    assert!(result.contains(PagePermissions::READ));
    assert!(!result.contains(PagePermissions::WRITE));
    assert!(!result.contains(PagePermissions::EXECUTE));
}

#[test]
fn test_page_mapping_new() {
    let va = VirtAddr::new(0x1000);
    let pa = PhysAddr::new(0x2000);
    let perms = PagePermissions::READ | PagePermissions::WRITE;
    let mapping = PageMapping::new(va, pa, PageSize::Size4KiB, perms);
    assert_eq!(mapping.virtual_addr, va);
    assert_eq!(mapping.physical_addr, pa);
    assert_eq!(mapping.size, PageSize::Size4KiB);
    assert_eq!(mapping.reference_count, 1);
    assert!(mapping.process_id.is_none());
}

#[test]
fn test_page_mapping_kernel() {
    let va = VirtAddr::new(0xFFFF_FFFF_8000_0000);
    let pa = PhysAddr::new(0x1000);
    let perms = PagePermissions::READ | PagePermissions::EXECUTE;
    let mapping = PageMapping::kernel(va, pa, perms);
    assert!(mapping.is_kernel());
    assert!(!mapping.is_user());
}

#[test]
fn test_page_mapping_user() {
    let va = VirtAddr::new(0x7FFF_0000_0000);
    let pa = PhysAddr::new(0x1000);
    let perms = PagePermissions::READ | PagePermissions::USER;
    let mapping = PageMapping::user(va, pa, perms, 42);
    assert!(mapping.is_user());
    assert!(!mapping.is_kernel());
    assert_eq!(mapping.process_id, Some(42));
}

#[test]
fn test_page_mapping_is_huge_4k() {
    let mapping = PageMapping::new(
        VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        PageSize::Size4KiB, PagePermissions::READ
    );
    assert!(!mapping.is_huge());
}

#[test]
fn test_page_mapping_is_huge_2m() {
    let mapping = PageMapping::new(
        VirtAddr::new(0x200000), PhysAddr::new(0x200000),
        PageSize::Size2MiB, PagePermissions::READ
    );
    assert!(mapping.is_huge());
}

#[test]
fn test_page_mapping_is_huge_1g() {
    let mapping = PageMapping::new(
        VirtAddr::new(0x40000000), PhysAddr::new(0x40000000),
        PageSize::Size1GiB, PagePermissions::READ
    );
    assert!(mapping.is_huge());
}

#[test]
fn test_page_mapping_is_shared_by_refcount() {
    let mut mapping = PageMapping::new(
        VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        PageSize::Size4KiB, PagePermissions::READ
    );
    mapping.reference_count = 2;
    assert!(mapping.is_shared());
}

#[test]
fn test_page_mapping_is_shared_by_flag() {
    let mapping = PageMapping::new(
        VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        PageSize::Size4KiB, PagePermissions::READ | PagePermissions::SHARED
    );
    assert!(mapping.is_shared());
}

#[test]
fn test_page_mapping_touch() {
    let mut mapping = PageMapping::new(
        VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        PageSize::Size4KiB, PagePermissions::READ
    );
    let old_time = mapping.last_accessed;
    mapping.touch();
    assert!(mapping.last_accessed >= old_time);
}

#[test]
fn test_page_fault_info_from_fault() {
    let info = PageFaultInfo::from_fault(0x1000, 0x07);
    assert_eq!(info.address, 0x1000);
    assert_eq!(info.error_code, 0x07);
    assert!(info.is_write);
    assert!(info.is_user);
    assert!(info.page_was_present);
}

#[test]
fn test_page_fault_info_is_write() {
    let write_fault = PageFaultInfo::from_fault(0x1000, 0x02);
    let read_fault = PageFaultInfo::from_fault(0x1000, 0x00);
    assert!(write_fault.is_write);
    assert!(!read_fault.is_write);
}

#[test]
fn test_page_fault_info_is_user() {
    let user_fault = PageFaultInfo::from_fault(0x1000, 0x04);
    let kernel_fault = PageFaultInfo::from_fault(0x1000, 0x00);
    assert!(user_fault.is_user);
    assert!(!kernel_fault.is_user);
}

#[test]
fn test_page_fault_info_is_instruction_fetch() {
    let fetch_fault = PageFaultInfo::from_fault(0x1000, 0x10);
    let data_fault = PageFaultInfo::from_fault(0x1000, 0x00);
    assert!(fetch_fault.is_instruction_fetch);
    assert!(!data_fault.is_instruction_fetch);
}

#[test]
fn test_page_fault_info_page_was_present() {
    let present = PageFaultInfo::from_fault(0x1000, 0x01);
    let not_present = PageFaultInfo::from_fault(0x1000, 0x00);
    assert!(present.page_was_present);
    assert!(!not_present.page_was_present);
}

#[test]
fn test_page_fault_info_is_cow_fault() {
    let cow = PageFaultInfo::from_fault(0x1000, 0x03);
    let not_cow = PageFaultInfo::from_fault(0x1000, 0x02);
    assert!(cow.is_cow_fault());
    assert!(!not_cow.is_cow_fault());
}

#[test]
fn test_page_fault_info_is_demand_fault() {
    let demand = PageFaultInfo::from_fault(0x1000, 0x00);
    let not_demand = PageFaultInfo::from_fault(0x1000, 0x01);
    assert!(demand.is_demand_fault());
    assert!(!not_demand.is_demand_fault());
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
fn test_pte_masks() {
    assert_eq!(PTE_ADDR_MASK, 0x000F_FFFF_FFFF_F000);
    assert_eq!(PTE_FLAGS_MASK, 0xFFF0_0000_0000_0FFF);
}

#[test]
fn test_pte_table_flags() {
    assert_eq!(PTE_TABLE_FLAGS, PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    assert_eq!(PTE_KERNEL_TABLE, PTE_PRESENT | PTE_WRITABLE);
}

#[test]
fn test_page_table_entries() {
    assert_eq!(PAGE_TABLE_ENTRIES, 512);
}

#[test]
fn test_index_shifts() {
    assert_eq!(PML4_SHIFT, 39);
    assert_eq!(PDPT_SHIFT, 30);
    assert_eq!(PD_SHIFT, 21);
    assert_eq!(PT_SHIFT, 12);
}

#[test]
fn test_index_mask() {
    assert_eq!(INDEX_MASK, 0x1FF);
}

#[test]
fn test_page_offset_mask() {
    assert_eq!(PAGE_OFFSET_MASK, 0xFFF);
}

#[test]
fn test_page_sizes_constants() {
    assert_eq!(PAGE_SIZE_4K, 4096);
    assert_eq!(PAGE_SIZE_2M, 2 * 1024 * 1024);
    assert_eq!(PAGE_SIZE_1G, 1024 * 1024 * 1024);
}

#[test]
fn test_permission_constants() {
    assert_eq!(PERM_READ, 1 << 0);
    assert_eq!(PERM_WRITE, 1 << 1);
    assert_eq!(PERM_EXECUTE, 1 << 2);
    assert_eq!(PERM_USER, 1 << 3);
    assert_eq!(PERM_GLOBAL, 1 << 4);
    assert_eq!(PERM_NO_CACHE, 1 << 5);
    assert_eq!(PERM_WRITE_THROUGH, 1 << 6);
    assert_eq!(PERM_COW, 1 << 7);
    assert_eq!(PERM_DEMAND, 1 << 8);
    assert_eq!(PERM_ZERO_FILL, 1 << 9);
    assert_eq!(PERM_SHARED, 1 << 10);
    assert_eq!(PERM_LOCKED, 1 << 11);
    assert_eq!(PERM_DEVICE, 1 << 12);
}

#[test]
fn test_pml4_index() {
    assert_eq!(pml4_index(0), 0);
    assert_eq!(pml4_index(1u64 << 39), 1);
    assert_eq!(pml4_index(0xFFFF_FFFF_FFFF_FFFF), 511);
}

#[test]
fn test_pdpt_index() {
    assert_eq!(pdpt_index(0), 0);
    assert_eq!(pdpt_index(1u64 << 30), 1);
}

#[test]
fn test_pd_index() {
    assert_eq!(pd_index(0), 0);
    assert_eq!(pd_index(1u64 << 21), 1);
}

#[test]
fn test_pt_index() {
    assert_eq!(pt_index(0), 0);
    assert_eq!(pt_index(1u64 << 12), 1);
}

#[test]
fn test_page_offset() {
    assert_eq!(page_offset(0), 0);
    assert_eq!(page_offset(0xFFF), 0xFFF);
    assert_eq!(page_offset(0x1000), 0);
}

#[test]
fn test_pte_is_present_true() {
    assert!(pte_is_present(PTE_PRESENT));
}

#[test]
fn test_pte_is_present_false() {
    assert!(!pte_is_present(0));
}

#[test]
fn test_pte_is_huge_true() {
    assert!(pte_is_huge(PTE_HUGE_PAGE));
}

#[test]
fn test_pte_is_huge_false() {
    assert!(!pte_is_huge(PTE_PRESENT));
}

#[test]
fn test_pte_address() {
    let pte = 0x12345_000 | PTE_PRESENT;
    assert_eq!(pte_address(pte), 0x12345_000);
}

#[test]
fn test_page_align_down() {
    assert_eq!(page_align_down(0x1234), 0x1000);
    assert_eq!(page_align_down(0x1000), 0x1000);
}

#[test]
fn test_page_align_up() {
    assert_eq!(page_align_up(0x1234), 0x2000);
    assert_eq!(page_align_up(0x1000), 0x1000);
}

#[test]
fn test_pages_needed_paging() {
    assert_eq!(pages_needed(0), 0);
    assert_eq!(pages_needed(1), 1);
    assert_eq!(pages_needed(4096), 1);
    assert_eq!(pages_needed(4097), 2);
}

#[test]
fn test_paging_error_variants() {
    assert_eq!(PagingError::NotInitialized, PagingError::NotInitialized);
    assert_eq!(PagingError::NoActivePageTable, PagingError::NoActivePageTable);
    assert_eq!(PagingError::FrameAllocationFailed, PagingError::FrameAllocationFailed);
    assert_eq!(PagingError::PageNotMapped, PagingError::PageNotMapped);
    assert_eq!(PagingError::Pml4NotPresent, PagingError::Pml4NotPresent);
    assert_eq!(PagingError::PdptNotPresent, PagingError::PdptNotPresent);
    assert_eq!(PagingError::PdNotPresent, PagingError::PdNotPresent);
    assert_eq!(PagingError::PtNotPresent, PagingError::PtNotPresent);
    assert_eq!(PagingError::AddressSpaceNotFound, PagingError::AddressSpaceNotFound);
    assert_eq!(PagingError::InvalidAddress, PagingError::InvalidAddress);
    assert_eq!(PagingError::WXViolation, PagingError::WXViolation);
    assert_eq!(PagingError::AlreadyMapped, PagingError::AlreadyMapped);
    assert_eq!(PagingError::PermissionDenied, PagingError::PermissionDenied);
    assert_eq!(PagingError::UnhandledPageFault, PagingError::UnhandledPageFault);
    assert_eq!(PagingError::CowFaultFailed, PagingError::CowFaultFailed);
    assert_eq!(PagingError::DemandFaultFailed, PagingError::DemandFaultFailed);
    assert_eq!(PagingError::InvalidPageSize, PagingError::InvalidPageSize);
    assert_eq!(PagingError::NotAligned, PagingError::NotAligned);
    assert_eq!(PagingError::KernelSpaceViolation, PagingError::KernelSpaceViolation);
}

#[test]
fn test_aslr_enabled_default() {
    set_aslr_enabled(true);
    assert!(is_aslr_enabled());
}

#[test]
fn test_aslr_enabled_toggle() {
    set_aslr_enabled(false);
    assert!(!is_aslr_enabled());
    set_aslr_enabled(true);
    assert!(is_aslr_enabled());
}

#[test]
fn test_page_size_clone() {
    let size = PageSize::Size2MiB;
    let cloned = size.clone();
    assert_eq!(size, cloned);
}

#[test]
fn test_page_permissions_clone() {
    let perms = PagePermissions::READ | PagePermissions::WRITE;
    let cloned = perms.clone();
    assert_eq!(perms.bits(), cloned.bits());
}

#[test]
fn test_page_mapping_clone() {
    let mapping = PageMapping::new(
        VirtAddr::new(0x1000), PhysAddr::new(0x2000),
        PageSize::Size4KiB, PagePermissions::READ
    );
    let cloned = mapping.clone();
    assert_eq!(mapping.virtual_addr, cloned.virtual_addr);
    assert_eq!(mapping.physical_addr, cloned.physical_addr);
}

#[test]
fn test_page_fault_info_clone() {
    let info = PageFaultInfo::from_fault(0x1000, 0x07);
    let cloned = info.clone();
    assert_eq!(info.address, cloned.address);
    assert_eq!(info.error_code, cloned.error_code);
}

#[test]
fn test_paging_error_clone() {
    let err = PagingError::PageNotMapped;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_page_permissions_default() {
    let perms = PagePermissions::default();
    assert_eq!(perms.bits(), 0);
}

#[test]
fn test_all_permission_flags() {
    assert!(PagePermissions::READ.contains(PagePermissions::READ));
    assert!(PagePermissions::WRITE.contains(PagePermissions::WRITE));
    assert!(PagePermissions::EXECUTE.contains(PagePermissions::EXECUTE));
    assert!(PagePermissions::USER.contains(PagePermissions::USER));
    assert!(PagePermissions::GLOBAL.contains(PagePermissions::GLOBAL));
    assert!(PagePermissions::NO_CACHE.contains(PagePermissions::NO_CACHE));
    assert!(PagePermissions::WRITE_THROUGH.contains(PagePermissions::WRITE_THROUGH));
    assert!(PagePermissions::COW.contains(PagePermissions::COW));
    assert!(PagePermissions::DEMAND.contains(PagePermissions::DEMAND));
    assert!(PagePermissions::ZERO_FILL.contains(PagePermissions::ZERO_FILL));
    assert!(PagePermissions::SHARED.contains(PagePermissions::SHARED));
    assert!(PagePermissions::LOCKED.contains(PagePermissions::LOCKED));
    assert!(PagePermissions::DEVICE.contains(PagePermissions::DEVICE));
}

#[test]
fn test_combined_pte_flags() {
    let combined = PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NO_EXECUTE;
    assert_eq!(combined & PTE_PRESENT, PTE_PRESENT);
    assert_eq!(combined & PTE_WRITABLE, PTE_WRITABLE);
    assert_eq!(combined & PTE_USER, PTE_USER);
    assert_eq!(combined & PTE_NO_EXECUTE, PTE_NO_EXECUTE);
}

#[test]
fn test_index_boundary_values() {
    let max_addr = 0xFFFF_FFFF_FFFF_FFFFu64;
    assert_eq!(pml4_index(max_addr), 511);
    assert_eq!(pdpt_index(max_addr), 511);
    assert_eq!(pd_index(max_addr), 511);
    assert_eq!(pt_index(max_addr), 511);
    assert_eq!(page_offset(max_addr), 0xFFF);
}

#[test]
fn test_pte_address_extraction() {
    let addr = 0xABCDE_000u64;
    let pte = addr | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
    assert_eq!(pte_address(pte), addr);
}
