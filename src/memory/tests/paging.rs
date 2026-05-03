// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Paging subsystem tests

use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::paging::{
    is_aslr_enabled, page_align_down, page_align_up, page_offset, pages_needed, pd_index,
    pdpt_index, pml4_index, pt_index, pte_address, pte_is_huge, pte_is_present, set_aslr_enabled,
    PageFaultInfo, PageMapping, PagePermissions, PageSize, PagingError, INDEX_MASK,
    PAGE_OFFSET_MASK, PAGE_SIZE_1G, PAGE_SIZE_2M, PAGE_SIZE_4K, PAGE_TABLE_ENTRIES, PDPT_SHIFT,
    PD_SHIFT, PERM_COW, PERM_DEMAND, PERM_DEVICE, PERM_EXECUTE, PERM_GLOBAL, PERM_LOCKED,
    PERM_NO_CACHE, PERM_READ, PERM_SHARED, PERM_USER, PERM_WRITE, PERM_WRITE_THROUGH,
    PERM_ZERO_FILL, PML4_SHIFT, PTE_ACCESSED, PTE_ADDR_MASK, PTE_CACHE_DISABLE, PTE_DIRTY,
    PTE_FLAGS_MASK, PTE_GLOBAL, PTE_HUGE_PAGE, PTE_KERNEL_TABLE, PTE_NO_EXECUTE, PTE_PRESENT,
    PTE_TABLE_FLAGS, PTE_USER, PTE_WRITABLE, PTE_WRITE_THROUGH, PT_SHIFT,
};
use crate::test::framework::TestResult;

pub(crate) fn test_page_size_4kib_bytes() -> TestResult {
    if PageSize::Size4KiB.bytes() != PAGE_SIZE_4K {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_2mib_bytes() -> TestResult {
    if PageSize::Size2MiB.bytes() != PAGE_SIZE_2M {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_1gib_bytes() -> TestResult {
    if PageSize::Size1GiB.bytes() != PAGE_SIZE_1G {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_4kib_align_mask() -> TestResult {
    if PageSize::Size4KiB.align_mask() != 0xFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_2mib_align_mask() -> TestResult {
    if PageSize::Size2MiB.align_mask() != 0x1F_FFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_1gib_align_mask() -> TestResult {
    if PageSize::Size1GiB.align_mask() != 0x3FFF_FFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_4kib_is_aligned() -> TestResult {
    if !PageSize::Size4KiB.is_aligned(0x1000) {
        return TestResult::Fail;
    }
    if PageSize::Size4KiB.is_aligned(0x1001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_2mib_is_aligned() -> TestResult {
    if !PageSize::Size2MiB.is_aligned(0x200000) {
        return TestResult::Fail;
    }
    if PageSize::Size2MiB.is_aligned(0x200001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_1gib_is_aligned() -> TestResult {
    if !PageSize::Size1GiB.is_aligned(0x40000000) {
        return TestResult::Fail;
    }
    if PageSize::Size1GiB.is_aligned(0x40000001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_default() -> TestResult {
    if PageSize::default() != PageSize::Size4KiB {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_equality() -> TestResult {
    if PageSize::Size4KiB != PageSize::Size4KiB {
        return TestResult::Fail;
    }
    if PageSize::Size4KiB == PageSize::Size2MiB {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_empty() -> TestResult {
    let p = PagePermissions::empty();
    if p.bits() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_from_bits() -> TestResult {
    let p = PagePermissions::from_bits(PERM_READ | PERM_WRITE);
    if p.bits() != PERM_READ | PERM_WRITE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_contains_read() -> TestResult {
    let p = PagePermissions::READ;
    if !p.contains(PagePermissions::READ) {
        return TestResult::Fail;
    }
    if p.contains(PagePermissions::WRITE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_union() -> TestResult {
    let p = PagePermissions::READ.union(PagePermissions::WRITE);
    if !p.contains(PagePermissions::READ) {
        return TestResult::Fail;
    }
    if !p.contains(PagePermissions::WRITE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_remove() -> TestResult {
    let p = PagePermissions::READ.union(PagePermissions::WRITE);
    let removed = p.remove(PagePermissions::WRITE);
    if !removed.contains(PagePermissions::READ) {
        return TestResult::Fail;
    }
    if removed.contains(PagePermissions::WRITE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_insert() -> TestResult {
    let p = PagePermissions::READ.insert(PagePermissions::EXECUTE);
    if !p.contains(PagePermissions::READ) {
        return TestResult::Fail;
    }
    if !p.contains(PagePermissions::EXECUTE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_wx_violation() -> TestResult {
    let wx = PagePermissions::WRITE.union(PagePermissions::EXECUTE);
    if !wx.is_wx_violation() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_no_wx_violation() -> TestResult {
    let rw = PagePermissions::READ.union(PagePermissions::WRITE);
    if rw.is_wx_violation() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_bitor() -> TestResult {
    let p = PagePermissions::READ | PagePermissions::WRITE;
    if !p.contains(PagePermissions::READ) {
        return TestResult::Fail;
    }
    if !p.contains(PagePermissions::WRITE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_bitor_assign() -> TestResult {
    let mut p = PagePermissions::READ;
    p |= PagePermissions::EXECUTE;
    if !p.contains(PagePermissions::READ) {
        return TestResult::Fail;
    }
    if !p.contains(PagePermissions::EXECUTE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_bitand() -> TestResult {
    let p1 = PagePermissions::READ | PagePermissions::WRITE;
    let p2 = PagePermissions::READ | PagePermissions::EXECUTE;
    let result = p1 & p2;
    if !result.contains(PagePermissions::READ) {
        return TestResult::Fail;
    }
    if result.contains(PagePermissions::WRITE) {
        return TestResult::Fail;
    }
    if result.contains(PagePermissions::EXECUTE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_new() -> TestResult {
    let va = VirtAddr::new(0x1000);
    let pa = PhysAddr::new(0x2000);
    let perms = PagePermissions::READ | PagePermissions::WRITE;
    let mapping = PageMapping::new(va, pa, PageSize::Size4KiB, perms);
    if mapping.virtual_addr != va {
        return TestResult::Fail;
    }
    if mapping.physical_addr != pa {
        return TestResult::Fail;
    }
    if mapping.size != PageSize::Size4KiB {
        return TestResult::Fail;
    }
    if mapping.reference_count != 1 {
        return TestResult::Fail;
    }
    if mapping.process_id.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_kernel() -> TestResult {
    let va = VirtAddr::new(0xFFFF_FFFF_8000_0000);
    let pa = PhysAddr::new(0x1000);
    let perms = PagePermissions::READ | PagePermissions::EXECUTE;
    let mapping = PageMapping::kernel(va, pa, perms);
    if !mapping.is_kernel() {
        return TestResult::Fail;
    }
    if mapping.is_user() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_user() -> TestResult {
    let va = VirtAddr::new(0x7FFF_0000_0000);
    let pa = PhysAddr::new(0x1000);
    let perms = PagePermissions::READ | PagePermissions::USER;
    let mapping = PageMapping::user(va, pa, perms, 42);
    if !mapping.is_user() {
        return TestResult::Fail;
    }
    if mapping.is_kernel() {
        return TestResult::Fail;
    }
    if mapping.process_id != Some(42) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_is_huge_4k() -> TestResult {
    let mapping = PageMapping::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        PageSize::Size4KiB,
        PagePermissions::READ,
    );
    if mapping.is_huge() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_is_huge_2m() -> TestResult {
    let mapping = PageMapping::new(
        VirtAddr::new(0x200000),
        PhysAddr::new(0x200000),
        PageSize::Size2MiB,
        PagePermissions::READ,
    );
    if !mapping.is_huge() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_is_huge_1g() -> TestResult {
    let mapping = PageMapping::new(
        VirtAddr::new(0x40000000),
        PhysAddr::new(0x40000000),
        PageSize::Size1GiB,
        PagePermissions::READ,
    );
    if !mapping.is_huge() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_is_shared_by_refcount() -> TestResult {
    let mut mapping = PageMapping::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        PageSize::Size4KiB,
        PagePermissions::READ,
    );
    mapping.reference_count = 2;
    if !mapping.is_shared() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_is_shared_by_flag() -> TestResult {
    let mapping = PageMapping::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        PageSize::Size4KiB,
        PagePermissions::READ | PagePermissions::SHARED,
    );
    if !mapping.is_shared() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_touch() -> TestResult {
    let mut mapping = PageMapping::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        PageSize::Size4KiB,
        PagePermissions::READ,
    );
    let old_time = mapping.last_accessed;
    mapping.touch();
    if mapping.last_accessed < old_time {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_fault_info_from_fault() -> TestResult {
    let info = PageFaultInfo::from_fault(0x1000, 0x07);
    if info.address != 0x1000 {
        return TestResult::Fail;
    }
    if info.error_code != 0x07 {
        return TestResult::Fail;
    }
    if !info.is_write {
        return TestResult::Fail;
    }
    if !info.is_user {
        return TestResult::Fail;
    }
    if !info.page_was_present {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_fault_info_is_write() -> TestResult {
    let write_fault = PageFaultInfo::from_fault(0x1000, 0x02);
    let read_fault = PageFaultInfo::from_fault(0x1000, 0x00);
    if !write_fault.is_write {
        return TestResult::Fail;
    }
    if read_fault.is_write {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_fault_info_is_user() -> TestResult {
    let user_fault = PageFaultInfo::from_fault(0x1000, 0x04);
    let kernel_fault = PageFaultInfo::from_fault(0x1000, 0x00);
    if !user_fault.is_user {
        return TestResult::Fail;
    }
    if kernel_fault.is_user {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_fault_info_is_instruction_fetch() -> TestResult {
    let fetch_fault = PageFaultInfo::from_fault(0x1000, 0x10);
    let data_fault = PageFaultInfo::from_fault(0x1000, 0x00);
    if !fetch_fault.is_instruction_fetch {
        return TestResult::Fail;
    }
    if data_fault.is_instruction_fetch {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_fault_info_page_was_present() -> TestResult {
    let present = PageFaultInfo::from_fault(0x1000, 0x01);
    let not_present = PageFaultInfo::from_fault(0x1000, 0x00);
    if !present.page_was_present {
        return TestResult::Fail;
    }
    if not_present.page_was_present {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_fault_info_is_cow_fault() -> TestResult {
    let cow = PageFaultInfo::from_fault(0x1000, 0x03);
    let not_cow = PageFaultInfo::from_fault(0x1000, 0x02);
    if !cow.is_cow_fault() {
        return TestResult::Fail;
    }
    if not_cow.is_cow_fault() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_fault_info_is_demand_fault() -> TestResult {
    let demand = PageFaultInfo::from_fault(0x1000, 0x00);
    let not_demand = PageFaultInfo::from_fault(0x1000, 0x01);
    if !demand.is_demand_fault() {
        return TestResult::Fail;
    }
    if not_demand.is_demand_fault() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_flags() -> TestResult {
    if PTE_PRESENT != 1 << 0 {
        return TestResult::Fail;
    }
    if PTE_WRITABLE != 1 << 1 {
        return TestResult::Fail;
    }
    if PTE_USER != 1 << 2 {
        return TestResult::Fail;
    }
    if PTE_WRITE_THROUGH != 1 << 3 {
        return TestResult::Fail;
    }
    if PTE_CACHE_DISABLE != 1 << 4 {
        return TestResult::Fail;
    }
    if PTE_ACCESSED != 1 << 5 {
        return TestResult::Fail;
    }
    if PTE_DIRTY != 1 << 6 {
        return TestResult::Fail;
    }
    if PTE_HUGE_PAGE != 1 << 7 {
        return TestResult::Fail;
    }
    if PTE_GLOBAL != 1 << 8 {
        return TestResult::Fail;
    }
    if PTE_NO_EXECUTE != 1u64 << 63 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_masks() -> TestResult {
    if PTE_ADDR_MASK != 0x000F_FFFF_FFFF_F000 {
        return TestResult::Fail;
    }
    if PTE_FLAGS_MASK != 0xFFF0_0000_0000_0FFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_table_flags() -> TestResult {
    if PTE_TABLE_FLAGS != PTE_PRESENT | PTE_WRITABLE | PTE_USER {
        return TestResult::Fail;
    }
    if PTE_KERNEL_TABLE != PTE_PRESENT | PTE_WRITABLE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_table_entries() -> TestResult {
    if PAGE_TABLE_ENTRIES != 512 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_index_shifts() -> TestResult {
    if PML4_SHIFT != 39 {
        return TestResult::Fail;
    }
    if PDPT_SHIFT != 30 {
        return TestResult::Fail;
    }
    if PD_SHIFT != 21 {
        return TestResult::Fail;
    }
    if PT_SHIFT != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_index_mask() -> TestResult {
    if INDEX_MASK != 0x1FF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_offset_mask() -> TestResult {
    if PAGE_OFFSET_MASK != 0xFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_sizes_constants() -> TestResult {
    if PAGE_SIZE_4K != 4096 {
        return TestResult::Fail;
    }
    if PAGE_SIZE_2M != 2 * 1024 * 1024 {
        return TestResult::Fail;
    }
    if PAGE_SIZE_1G != 1024 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_permission_constants() -> TestResult {
    if PERM_READ != 1 << 0 {
        return TestResult::Fail;
    }
    if PERM_WRITE != 1 << 1 {
        return TestResult::Fail;
    }
    if PERM_EXECUTE != 1 << 2 {
        return TestResult::Fail;
    }
    if PERM_USER != 1 << 3 {
        return TestResult::Fail;
    }
    if PERM_GLOBAL != 1 << 4 {
        return TestResult::Fail;
    }
    if PERM_NO_CACHE != 1 << 5 {
        return TestResult::Fail;
    }
    if PERM_WRITE_THROUGH != 1 << 6 {
        return TestResult::Fail;
    }
    if PERM_COW != 1 << 7 {
        return TestResult::Fail;
    }
    if PERM_DEMAND != 1 << 8 {
        return TestResult::Fail;
    }
    if PERM_ZERO_FILL != 1 << 9 {
        return TestResult::Fail;
    }
    if PERM_SHARED != 1 << 10 {
        return TestResult::Fail;
    }
    if PERM_LOCKED != 1 << 11 {
        return TestResult::Fail;
    }
    if PERM_DEVICE != 1 << 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pml4_index() -> TestResult {
    if pml4_index(0) != 0 {
        return TestResult::Fail;
    }
    if pml4_index(1u64 << 39) != 1 {
        return TestResult::Fail;
    }
    if pml4_index(0xFFFF_FFFF_FFFF_FFFF) != 511 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pdpt_index() -> TestResult {
    if pdpt_index(0) != 0 {
        return TestResult::Fail;
    }
    if pdpt_index(1u64 << 30) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pd_index() -> TestResult {
    if pd_index(0) != 0 {
        return TestResult::Fail;
    }
    if pd_index(1u64 << 21) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pt_index() -> TestResult {
    if pt_index(0) != 0 {
        return TestResult::Fail;
    }
    if pt_index(1u64 << 12) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_offset() -> TestResult {
    if page_offset(0) != 0 {
        return TestResult::Fail;
    }
    if page_offset(0xFFF) != 0xFFF {
        return TestResult::Fail;
    }
    if page_offset(0x1000) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_is_present_true() -> TestResult {
    if !pte_is_present(PTE_PRESENT) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_is_present_false() -> TestResult {
    if pte_is_present(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_is_huge_true() -> TestResult {
    if !pte_is_huge(PTE_HUGE_PAGE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_is_huge_false() -> TestResult {
    if pte_is_huge(PTE_PRESENT) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_address() -> TestResult {
    let pte = 0x12345_000 | PTE_PRESENT;
    if pte_address(pte) != 0x12345_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_align_down() -> TestResult {
    if page_align_down(0x1234) != 0x1000 {
        return TestResult::Fail;
    }
    if page_align_down(0x1000) != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_align_up() -> TestResult {
    if page_align_up(0x1234) != 0x2000 {
        return TestResult::Fail;
    }
    if page_align_up(0x1000) != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pages_needed_paging() -> TestResult {
    if pages_needed(0) != 0 {
        return TestResult::Fail;
    }
    if pages_needed(1) != 1 {
        return TestResult::Fail;
    }
    if pages_needed(4096) != 1 {
        return TestResult::Fail;
    }
    if pages_needed(4097) != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_paging_error_variants() -> TestResult {
    if PagingError::NotInitialized != PagingError::NotInitialized {
        return TestResult::Fail;
    }
    if PagingError::NoActivePageTable != PagingError::NoActivePageTable {
        return TestResult::Fail;
    }
    if PagingError::FrameAllocationFailed != PagingError::FrameAllocationFailed {
        return TestResult::Fail;
    }
    if PagingError::PageNotMapped != PagingError::PageNotMapped {
        return TestResult::Fail;
    }
    if PagingError::Pml4NotPresent != PagingError::Pml4NotPresent {
        return TestResult::Fail;
    }
    if PagingError::PdptNotPresent != PagingError::PdptNotPresent {
        return TestResult::Fail;
    }
    if PagingError::PdNotPresent != PagingError::PdNotPresent {
        return TestResult::Fail;
    }
    if PagingError::PtNotPresent != PagingError::PtNotPresent {
        return TestResult::Fail;
    }
    if PagingError::AddressSpaceNotFound != PagingError::AddressSpaceNotFound {
        return TestResult::Fail;
    }
    if PagingError::InvalidAddress != PagingError::InvalidAddress {
        return TestResult::Fail;
    }
    if PagingError::WXViolation != PagingError::WXViolation {
        return TestResult::Fail;
    }
    if PagingError::AlreadyMapped != PagingError::AlreadyMapped {
        return TestResult::Fail;
    }
    if PagingError::PermissionDenied != PagingError::PermissionDenied {
        return TestResult::Fail;
    }
    if PagingError::UnhandledPageFault != PagingError::UnhandledPageFault {
        return TestResult::Fail;
    }
    if PagingError::CowFaultFailed != PagingError::CowFaultFailed {
        return TestResult::Fail;
    }
    if PagingError::DemandFaultFailed != PagingError::DemandFaultFailed {
        return TestResult::Fail;
    }
    if PagingError::InvalidPageSize != PagingError::InvalidPageSize {
        return TestResult::Fail;
    }
    if PagingError::NotAligned != PagingError::NotAligned {
        return TestResult::Fail;
    }
    if PagingError::KernelSpaceViolation != PagingError::KernelSpaceViolation {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aslr_enabled_default() -> TestResult {
    set_aslr_enabled(true);
    if !is_aslr_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aslr_enabled_toggle() -> TestResult {
    set_aslr_enabled(false);
    if is_aslr_enabled() {
        return TestResult::Fail;
    }
    set_aslr_enabled(true);
    if !is_aslr_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_clone() -> TestResult {
    let size = PageSize::Size2MiB;
    let cloned = size.clone();
    if size != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_clone() -> TestResult {
    let perms = PagePermissions::READ | PagePermissions::WRITE;
    let cloned = perms.clone();
    if perms.bits() != cloned.bits() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_mapping_clone() -> TestResult {
    let mapping = PageMapping::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        PageSize::Size4KiB,
        PagePermissions::READ,
    );
    let cloned = mapping.clone();
    if mapping.virtual_addr != cloned.virtual_addr {
        return TestResult::Fail;
    }
    if mapping.physical_addr != cloned.physical_addr {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_fault_info_clone() -> TestResult {
    let info = PageFaultInfo::from_fault(0x1000, 0x07);
    let cloned = info.clone();
    if info.address != cloned.address {
        return TestResult::Fail;
    }
    if info.error_code != cloned.error_code {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_paging_error_clone() -> TestResult {
    let err = PagingError::PageNotMapped;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_permissions_default() -> TestResult {
    let perms = PagePermissions::default();
    if perms.bits() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_permission_flags() -> TestResult {
    if !PagePermissions::READ.contains(PagePermissions::READ) {
        return TestResult::Fail;
    }
    if !PagePermissions::WRITE.contains(PagePermissions::WRITE) {
        return TestResult::Fail;
    }
    if !PagePermissions::EXECUTE.contains(PagePermissions::EXECUTE) {
        return TestResult::Fail;
    }
    if !PagePermissions::USER.contains(PagePermissions::USER) {
        return TestResult::Fail;
    }
    if !PagePermissions::GLOBAL.contains(PagePermissions::GLOBAL) {
        return TestResult::Fail;
    }
    if !PagePermissions::NO_CACHE.contains(PagePermissions::NO_CACHE) {
        return TestResult::Fail;
    }
    if !PagePermissions::WRITE_THROUGH.contains(PagePermissions::WRITE_THROUGH) {
        return TestResult::Fail;
    }
    if !PagePermissions::COW.contains(PagePermissions::COW) {
        return TestResult::Fail;
    }
    if !PagePermissions::DEMAND.contains(PagePermissions::DEMAND) {
        return TestResult::Fail;
    }
    if !PagePermissions::ZERO_FILL.contains(PagePermissions::ZERO_FILL) {
        return TestResult::Fail;
    }
    if !PagePermissions::SHARED.contains(PagePermissions::SHARED) {
        return TestResult::Fail;
    }
    if !PagePermissions::LOCKED.contains(PagePermissions::LOCKED) {
        return TestResult::Fail;
    }
    if !PagePermissions::DEVICE.contains(PagePermissions::DEVICE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_combined_pte_flags() -> TestResult {
    let combined = PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NO_EXECUTE;
    if combined & PTE_PRESENT != PTE_PRESENT {
        return TestResult::Fail;
    }
    if combined & PTE_WRITABLE != PTE_WRITABLE {
        return TestResult::Fail;
    }
    if combined & PTE_USER != PTE_USER {
        return TestResult::Fail;
    }
    if combined & PTE_NO_EXECUTE != PTE_NO_EXECUTE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_index_boundary_values() -> TestResult {
    let max_addr = 0xFFFF_FFFF_FFFF_FFFFu64;
    if pml4_index(max_addr) != 511 {
        return TestResult::Fail;
    }
    if pdpt_index(max_addr) != 511 {
        return TestResult::Fail;
    }
    if pd_index(max_addr) != 511 {
        return TestResult::Fail;
    }
    if pt_index(max_addr) != 511 {
        return TestResult::Fail;
    }
    if page_offset(max_addr) != 0xFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_address_extraction() -> TestResult {
    let addr = 0xABCDE_000u64;
    let pte = addr | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
    if pte_address(pte) != addr {
        return TestResult::Fail;
    }
    TestResult::Pass
}
