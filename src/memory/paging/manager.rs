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

extern crate alloc;
use alloc::collections::BTreeMap;
use x86_64::registers::control::Cr3;
use x86_64::{PhysAddr, VirtAddr};
use super::constants::*;
use super::error::{PagingError, PagingResult};
use super::stats::PagingStatistics;
use super::tlb;
use super::types::{get_timestamp, AddressSpace, PageMapping, PagePermissions, PageSize};
use crate::memory::{frame_alloc, layout};
pub struct PagingManager {
    active_page_table: Option<PhysAddr>,
    mappings: BTreeMap<u64, PageMapping>,
    address_spaces: BTreeMap<u32, AddressSpace>,
    next_asid: u32,
    initialized: bool,
}

impl PagingManager {
    pub const fn new() -> Self {
        Self {
            active_page_table: None,
            mappings: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            next_asid: FIRST_USER_ASID,
            initialized: false,
        }
    }

    pub fn init(&mut self) -> PagingResult<()> {
        if self.initialized {
            return Ok(());
        }

        let (cr3_frame, _) = Cr3::read();
        self.active_page_table = Some(cr3_frame.start_address());
        self.initialized = true;
        self.create_kernel_address_space()?;
        Ok(())
    }

    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn active_page_table(&self) -> Option<PhysAddr> {
        self.active_page_table
    }

    pub fn mappings_count(&self) -> usize {
        self.mappings.len()
    }

    pub fn address_spaces_count(&self) -> usize {
        self.address_spaces.len()
    }

    // ========================================================================
    // ADDRESS SPACE MANAGEMENT
    // ========================================================================
    fn create_kernel_address_space(&mut self) -> PagingResult<()> {
        let cr3_value = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;
        let kernel_space = AddressSpace::new(KERNEL_ASID, cr3_value, 0);
        self.address_spaces.insert(KERNEL_ASID, kernel_space);
        Ok(())
    }

    pub fn create_address_space(&mut self, process_id: u32) -> PagingResult<u32> {
        let asid = self.next_asid;
        self.next_asid = self.next_asid.wrapping_add(1);
        let page_table_frame =
            frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
        let address_space = AddressSpace::new(asid, page_table_frame, process_id);
        self.address_spaces.insert(asid, address_space);
        self.initialize_address_space(page_table_frame)?;

        Ok(asid)
    }

    fn initialize_address_space(&self, page_table_pa: PhysAddr) -> PagingResult<()> {
        let page_table_va = layout::DIRECTMAP_BASE + page_table_pa.as_u64();
        // SAFETY: We just allocated this frame and will initialize it
        let page_table = unsafe { &mut *(page_table_va as *mut [u64; PAGE_TABLE_ENTRIES]) };
        for entry in page_table.iter_mut() {
            *entry = 0;
        }

        if let Some(kernel_cr3) = self.active_page_table {
            let kernel_table_va = layout::DIRECTMAP_BASE + kernel_cr3.as_u64();
            // SAFETY: Reading from valid kernel page table
            let kernel_table =
                unsafe { &*(kernel_table_va as *const [u64; PAGE_TABLE_ENTRIES]) };
            for i in KERNEL_PML4_START..PAGE_TABLE_ENTRIES {
                page_table[i] = kernel_table[i];
            }
        }

        Ok(())
    }

    pub fn switch_address_space(&mut self, asid: u32) -> PagingResult<()> {
        let address_space = self
            .address_spaces
            .get(&asid)
            .ok_or(PagingError::AddressSpaceNotFound)?;
        // SAFETY: Loading valid page table into CR3
        unsafe {
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) address_space.cr3_value.as_u64(),
                options(nostack, preserves_flags)
            );
        }

        self.active_page_table = Some(address_space.cr3_value);
        Ok(())
    }

    pub fn cleanup_address_space(&mut self, asid: u32) -> PagingResult<()> {
        if let Some(address_space) = self.address_spaces.remove(&asid) {
            for mapping_addr in &address_space.mappings {
                let _ = self.unmap_page(*mapping_addr);
            }

            frame_alloc::deallocate_frame(address_space.cr3_value);
        }

        Ok(())
    }
    // ========================================================================
    // PAGE MAPPING
    // ========================================================================
    pub fn map_page(
        &mut self,
        virtual_addr: VirtAddr,
        physical_addr: PhysAddr,
        permissions: PagePermissions,
        size: PageSize,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        if !self.initialized {
            return Err(PagingError::NotInitialized);
        }

        if permissions.is_wx_violation() {
            return Err(PagingError::WXViolation);
        }

        let pte_flags = permissions.to_pte_flags();
        self.install_mapping(virtual_addr, physical_addr, pte_flags)?;
        let mapping = PageMapping::new(virtual_addr, physical_addr, size, permissions);
        let page_addr = page_align_down(virtual_addr.as_u64());
        self.mappings.insert(page_addr, mapping);
        stats.record_mapping(permissions, size);
        Ok(())
    }

    fn install_mapping(
        &self,
        va: VirtAddr,
        pa: PhysAddr,
        flags: u64,
    ) -> PagingResult<()> {
        let va_val = va.as_u64();
        let l4_idx = pml4_index(va_val);
        let l3_idx = pdpt_index(va_val);
        let l2_idx = pd_index(va_val);
        let l1_idx = pt_index(va_val);
        let cr3 = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;
        // SAFETY: Walking and modifying page tables with proper validation
        unsafe {
            let l4_table =
                &mut *((layout::DIRECTMAP_BASE + cr3.as_u64()) as *mut [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l4_table[l4_idx]) {
                let new_table =
                    frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
                l4_table[l4_idx] = new_table.as_u64() | PTE_TABLE_FLAGS;
                let table_va = layout::DIRECTMAP_BASE + new_table.as_u64();
                core::ptr::write_bytes(table_va as *mut u8, 0, PAGE_SIZE_4K);
            }

            let l3_pa = PhysAddr::new(pte_address(l4_table[l4_idx]));
            let l3_table = &mut *((layout::DIRECTMAP_BASE + l3_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l3_table[l3_idx]) {
                let new_table =
                    frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
                l3_table[l3_idx] = new_table.as_u64() | PTE_TABLE_FLAGS;
                let table_va = layout::DIRECTMAP_BASE + new_table.as_u64();
                core::ptr::write_bytes(table_va as *mut u8, 0, PAGE_SIZE_4K);
            }

            let l2_pa = PhysAddr::new(pte_address(l3_table[l3_idx]));
            let l2_table = &mut *((layout::DIRECTMAP_BASE + l2_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l2_table[l2_idx]) {
                let new_table =
                    frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
                l2_table[l2_idx] = new_table.as_u64() | PTE_TABLE_FLAGS;
                let table_va = layout::DIRECTMAP_BASE + new_table.as_u64();
                core::ptr::write_bytes(table_va as *mut u8, 0, PAGE_SIZE_4K);
            }

            let l1_pa = PhysAddr::new(pte_address(l2_table[l2_idx]));
            let l1_table = &mut *((layout::DIRECTMAP_BASE + l1_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);
            l1_table[l1_idx] = pa.as_u64() | flags;
        }

        tlb::invalidate_page(va);
        Ok(())
    }

    pub fn unmap_page(
        &mut self,
        virtual_addr: VirtAddr,
    ) -> PagingResult<(PhysAddr, PagePermissions, PageSize)> {
        if !self.initialized {
            return Err(PagingError::NotInitialized);
        }

        let page_addr = page_align_down(virtual_addr.as_u64());
        let mapping = self
            .mappings
            .remove(&page_addr)
            .ok_or(PagingError::PageNotMapped)?;
        let physical_addr = self.remove_mapping(virtual_addr)?;
        Ok((physical_addr, mapping.permissions, mapping.size))
    }

    fn remove_mapping(&self, va: VirtAddr) -> PagingResult<PhysAddr> {
        let va_val = va.as_u64();
        let l4_idx = pml4_index(va_val);
        let l3_idx = pdpt_index(va_val);
        let l2_idx = pd_index(va_val);
        let l1_idx = pt_index(va_val);
        let cr3 = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;
        // SAFETY: Walking page tables with validation
        unsafe {
            let l4_table =
                &*((layout::DIRECTMAP_BASE + cr3.as_u64()) as *const [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l4_table[l4_idx]) {
                return Err(PagingError::Pml4NotPresent);
            }

            let l3_pa = PhysAddr::new(pte_address(l4_table[l4_idx]));
            let l3_table = &*((layout::DIRECTMAP_BASE + l3_pa.as_u64())
                as *const [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l3_table[l3_idx]) {
                return Err(PagingError::PdptNotPresent);
            }

            let l2_pa = PhysAddr::new(pte_address(l3_table[l3_idx]));
            let l2_table = &*((layout::DIRECTMAP_BASE + l2_pa.as_u64())
                as *const [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l2_table[l2_idx]) {
                return Err(PagingError::PdNotPresent);
            }

            let l1_pa = PhysAddr::new(pte_address(l2_table[l2_idx]));
            let l1_table = &mut *((layout::DIRECTMAP_BASE + l1_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l1_table[l1_idx]) {
                return Err(PagingError::PtNotPresent);
            }

            let physical_addr = PhysAddr::new(pte_address(l1_table[l1_idx]));
            l1_table[l1_idx] = 0;
            tlb::invalidate_page(va);
            Ok(physical_addr)
        }
    }

    // ========================================================================
    // ADDRESS TRANSLATION
    // ========================================================================
    pub fn translate_address(&self, virtual_addr: VirtAddr) -> PagingResult<PhysAddr> {
        let va_val = virtual_addr.as_u64();
        let l4_idx = pml4_index(va_val);
        let l3_idx = pdpt_index(va_val);
        let l2_idx = pd_index(va_val);
        let l1_idx = pt_index(va_val);
        let offset = page_offset(va_val);
        let cr3 = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;
        // SAFETY: Walking page tables with validation
        unsafe {
            let l4_table =
                &*((layout::DIRECTMAP_BASE + cr3.as_u64()) as *const [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l4_table[l4_idx]) {
                return Err(PagingError::Pml4NotPresent);
            }

            let l3_pa = PhysAddr::new(pte_address(l4_table[l4_idx]));
            let l3_table = &*((layout::DIRECTMAP_BASE + l3_pa.as_u64())
                as *const [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l3_table[l3_idx]) {
                return Err(PagingError::PdptNotPresent);
            }

            if pte_is_huge(l3_table[l3_idx]) {
                let page_pa = pte_address(l3_table[l3_idx]);
                let huge_offset = va_val & PageSize::Size1GiB.align_mask();
                return Ok(PhysAddr::new(page_pa + huge_offset));
            }

            let l2_pa = PhysAddr::new(pte_address(l3_table[l3_idx]));
            let l2_table = &*((layout::DIRECTMAP_BASE + l2_pa.as_u64())
                as *const [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l2_table[l2_idx]) {
                return Err(PagingError::PdNotPresent);
            }

            if pte_is_huge(l2_table[l2_idx]) {
                let page_pa = pte_address(l2_table[l2_idx]);
                let huge_offset = va_val & PageSize::Size2MiB.align_mask();
                return Ok(PhysAddr::new(page_pa + huge_offset));
            }

            let l1_pa = PhysAddr::new(pte_address(l2_table[l2_idx]));
            let l1_table = &*((layout::DIRECTMAP_BASE + l1_pa.as_u64())
                as *const [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l1_table[l1_idx]) {
                return Err(PagingError::PtNotPresent);
            }

            let page_pa = pte_address(l1_table[l1_idx]);
            Ok(PhysAddr::new(page_pa + offset as u64))
        }
    }

    // ========================================================================
    // PAGE PROTECTION
    // ========================================================================
    pub fn update_page_flags(
        &mut self,
        virtual_addr: VirtAddr,
        new_permissions: PagePermissions,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        if new_permissions.is_wx_violation() {
            return Err(PagingError::WXViolation);
        }

        let page_addr = page_align_down(virtual_addr.as_u64());

        let mapping = self
            .mappings
            .get_mut(&page_addr)
            .ok_or(PagingError::PageNotMapped)?;
        mapping.permissions = new_permissions;
        mapping.last_accessed = get_timestamp();
        let pte_flags = new_permissions.to_pte_flags();
        self.update_pte(virtual_addr, pte_flags)?;
        tlb::invalidate_page(virtual_addr);
        stats.record_modification();

        Ok(())
    }

    fn update_pte(&self, va: VirtAddr, new_flags: u64) -> PagingResult<()> {
        let va_val = va.as_u64();
        let l4_idx = pml4_index(va_val);
        let l3_idx = pdpt_index(va_val);
        let l2_idx = pd_index(va_val);
        let l1_idx = pt_index(va_val);
        let cr3 = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;
        // SAFETY: Walking page tables with validation
        unsafe {
            let l4_table =
                &*((layout::DIRECTMAP_BASE + cr3.as_u64()) as *const [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l4_table[l4_idx]) {
                return Err(PagingError::Pml4NotPresent);
            }

            let l3_pa = PhysAddr::new(pte_address(l4_table[l4_idx]));
            let l3_table = &mut *((layout::DIRECTMAP_BASE + l3_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l3_table[l3_idx]) {
                return Err(PagingError::PdptNotPresent);
            }

            if pte_is_huge(l3_table[l3_idx]) {
                let phys_addr = pte_address(l3_table[l3_idx]);
                l3_table[l3_idx] = phys_addr | new_flags | PTE_HUGE_PAGE;
                return Ok(());
            }

            let l2_pa = PhysAddr::new(pte_address(l3_table[l3_idx]));
            let l2_table = &mut *((layout::DIRECTMAP_BASE + l2_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l2_table[l2_idx]) {
                return Err(PagingError::PdNotPresent);
            }

            if pte_is_huge(l2_table[l2_idx]) {
                let phys_addr = pte_address(l2_table[l2_idx]);
                l2_table[l2_idx] = phys_addr | new_flags | PTE_HUGE_PAGE;
                return Ok(());
            }

            let l1_pa = PhysAddr::new(pte_address(l2_table[l2_idx]));
            let l1_table = &mut *((layout::DIRECTMAP_BASE + l1_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);
            if !pte_is_present(l1_table[l1_idx]) {
                return Err(PagingError::PtNotPresent);
            }

            let phys_addr = pte_address(l1_table[l1_idx]);
            l1_table[l1_idx] = phys_addr | new_flags;
        }

        Ok(())
    }

    // ========================================================================
    // PAGE FAULT HANDLING
    // ========================================================================
    pub fn handle_page_fault(
        &mut self,
        virtual_addr: VirtAddr,
        error_code: u64,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        stats.record_page_fault();
        if error_code & PF_WRITE != 0 && error_code & PF_PRESENT != 0 {
            stats.record_cow_fault();
            return self.handle_cow_fault(virtual_addr, stats);
        }

        if error_code & PF_PRESENT == 0 {
            stats.record_demand_load();
            return self.handle_demand_fault(virtual_addr, stats);
        }

        Err(PagingError::UnhandledPageFault)
    }

    fn handle_cow_fault(
        &mut self,
        virtual_addr: VirtAddr,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        let new_frame =
            frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
        if let Ok(original_pa) = self.translate_address(virtual_addr) {
            // SAFETY: Copying memory between valid frames
            unsafe {
                let src_va = layout::DIRECTMAP_BASE + original_pa.as_u64();
                let dst_va = layout::DIRECTMAP_BASE + new_frame.as_u64();
                core::ptr::copy_nonoverlapping(
                    src_va as *const u8,
                    dst_va as *mut u8,
                    PAGE_SIZE_4K,
                );
            }
        }

        let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::USER;
        self.map_page(
            virtual_addr,
            new_frame,
            permissions,
            PageSize::Size4KiB,
            stats,
        )?;
        Ok(())
    }

    /// Handles demand fault (zero-fill).
    fn handle_demand_fault(
        &mut self,
        virtual_addr: VirtAddr,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        let new_frame =
            frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
        // SAFETY: Zeroing newly allocated frame
        unsafe {
            let va = layout::DIRECTMAP_BASE + new_frame.as_u64();
            core::ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE_4K);
        }

        let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::USER;
        self.map_page(
            virtual_addr,
            new_frame,
            permissions,
            PageSize::Size4KiB,
            stats,
        )?;

        Ok(())
    }

    // ========================================================================
    // MAPPING INFO
    // ========================================================================
    pub fn get_mapping_info(&self, virtual_addr: VirtAddr) -> Option<&PageMapping> {
        let page_addr = page_align_down(virtual_addr.as_u64());
        self.mappings.get(&page_addr)
    }

    pub fn get_mapping_info_mut(&mut self, virtual_addr: VirtAddr) -> Option<&mut PageMapping> {
        let page_addr = page_align_down(virtual_addr.as_u64());
        self.mappings.get_mut(&page_addr)
    }
}

impl Default for PagingManager {
    fn default() -> Self {
        Self::new()
    }
}

// Public API
use spin::Mutex;
use super::types::PagingStats;
static PAGING_MANAGER: Mutex<PagingManager> = Mutex::new(PagingManager::new());
static PAGING_STATS: PagingStatistics = PagingStatistics::new();
pub fn init() -> PagingResult<()> { PAGING_MANAGER.lock().init() }
pub fn is_initialized() -> bool { PAGING_MANAGER.lock().is_initialized() }
pub fn map_page(virtual_addr: VirtAddr, physical_addr: PhysAddr, permissions: PagePermissions) -> PagingResult<()> {
    PAGING_MANAGER.lock().map_page(virtual_addr, physical_addr, permissions, PageSize::Size4KiB, &PAGING_STATS)
}

pub fn map_huge_page(virtual_addr: VirtAddr, physical_addr: PhysAddr, permissions: PagePermissions, size: PageSize) -> PagingResult<()> {
    PAGING_MANAGER.lock().map_page(virtual_addr, physical_addr, permissions, size, &PAGING_STATS)
}

pub fn unmap_page(virtual_addr: VirtAddr) -> PagingResult<PhysAddr> {
    let (phys, perms, size) = PAGING_MANAGER.lock().unmap_page(virtual_addr)?;
    PAGING_STATS.record_unmapping(perms, size);
    Ok(phys)
}

pub fn map_kernel_page(virtual_addr: VirtAddr, physical_addr: PhysAddr) -> PagingResult<()> {
    let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::GLOBAL;
    map_page(virtual_addr, physical_addr, permissions)
}

pub fn map_user_page(virtual_addr: VirtAddr, physical_addr: PhysAddr, writable: bool) -> PagingResult<()> {
    let mut permissions = PagePermissions::READ | PagePermissions::USER;
    if writable { permissions = permissions | PagePermissions::WRITE; }
    map_page(virtual_addr, physical_addr, permissions)
}

pub fn map_device_memory(virtual_addr: VirtAddr, physical_addr: PhysAddr, size: usize) -> PagingResult<()> {
    let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::NO_CACHE | PagePermissions::DEVICE;
    let page_count = pages_needed(size);
    for i in 0..page_count {
        let va = VirtAddr::new(virtual_addr.as_u64() + (i * PAGE_SIZE_4K) as u64);
        let pa = PhysAddr::new(physical_addr.as_u64() + (i * PAGE_SIZE_4K) as u64);
        map_page(va, pa, permissions)?;
    }
    Ok(())
}

pub fn translate_address(virtual_addr: VirtAddr) -> Option<PhysAddr> {
    PAGING_MANAGER.lock().translate_address(virtual_addr).ok()
}

pub fn is_mapped(virtual_addr: VirtAddr) -> bool { translate_address(virtual_addr).is_some() }
pub fn update_page_flags(virtual_addr: VirtAddr, new_permissions: PagePermissions) -> PagingResult<()> {
    PAGING_MANAGER.lock().update_page_flags(virtual_addr, new_permissions, &PAGING_STATS)
}

pub fn update_page_protection(virtual_addr: VirtAddr, permissions: PagePermissions) -> PagingResult<()> {
    update_page_flags(virtual_addr, permissions)
}

pub fn protect_pages(start_va: VirtAddr, page_count: usize, permissions: PagePermissions) -> PagingResult<()> {
    for i in 0..page_count {
        let va = VirtAddr::new(start_va.as_u64() + (i * PAGE_SIZE_4K) as u64);
        update_page_flags(va, permissions)?;
    }
    Ok(())
}

pub fn protect_pages_range(start_addr: VirtAddr, page_count: usize, permissions: PagePermissions) -> PagingResult<()> {
    protect_pages(start_addr, page_count, permissions)
}

pub fn create_address_space(process_id: u32) -> PagingResult<u32> { PAGING_MANAGER.lock().create_address_space(process_id) }
pub fn switch_address_space(asid: u32) -> PagingResult<()> { PAGING_MANAGER.lock().switch_address_space(asid) }
pub fn cleanup_address_space(asid: u32) -> PagingResult<()> { PAGING_MANAGER.lock().cleanup_address_space(asid) }
pub fn handle_page_fault(virtual_addr: VirtAddr, error_code: u64) -> PagingResult<()> {
    PAGING_MANAGER.lock().handle_page_fault(virtual_addr, error_code, &PAGING_STATS)
}

pub fn flush_tlb(virtual_addr: Option<VirtAddr>) -> PagingResult<()> {
    PAGING_STATS.record_tlb_flush();
    match virtual_addr {
        Some(addr) => super::tlb::invalidate_page(addr),
        None => super::tlb::invalidate_all(),
    }
    Ok(())
}

pub fn invalidate_page(va: VirtAddr) { super::tlb::invalidate_page(va); PAGING_STATS.record_tlb_flush(); }
pub fn invalidate_all_pages() { super::tlb::invalidate_all(); PAGING_STATS.record_tlb_flush(); }
pub fn get_current_cr3() -> PhysAddr { super::tlb::get_cr3() }
pub fn set_cr3(page_table_pa: PhysAddr) { super::tlb::set_cr3(page_table_pa); }
pub fn enable_write_protection() { super::tlb::enable_write_protection(); }

/// # Safety
/// Caller must re-enable write protection immediately after use.
pub unsafe fn disable_write_protection() { super::tlb::disable_write_protection(); }

pub fn get_mapping_info(virtual_addr: VirtAddr) -> Option<PageMapping> {
    PAGING_MANAGER.lock().get_mapping_info(virtual_addr).cloned()
}

pub fn get_page_permissions(virtual_addr: VirtAddr) -> Option<PagePermissions> {
    get_mapping_info(virtual_addr).map(|m| m.permissions)
}

pub fn get_paging_stats() -> PagingStats {
    let manager = PAGING_MANAGER.lock();
    PAGING_STATS.snapshot(manager.mappings_count(), manager.address_spaces_count())
}

pub fn get_memory_usage() -> (usize, usize) {
    let stats = get_paging_stats();
    (stats.user_pages * layout::PAGE_SIZE, stats.kernel_pages * layout::PAGE_SIZE)
}
