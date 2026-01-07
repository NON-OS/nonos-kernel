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
use alloc::vec::Vec;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::{PhysAddr, VirtAddr};
use super::constants::*;
use super::error::{VmError, VmResult};
use super::stats::VM_STATS;
use super::types::{MappedRange, PageSize, VmFlags};
use crate::memory::{frame_alloc, layout};
// ============================================================================
// VIRTUAL MEMORY MANAGER
// ============================================================================
pub struct VirtualMemoryManager {
    cr3_frame: PhysAddr,
    kernel_page_table: Option<VirtAddr>,
    mapped_ranges: Vec<MappedRange>,
    next_free_addr: u64,
    initialized: bool,
}

impl VirtualMemoryManager {
    pub const fn new() -> Self {
        Self {
            cr3_frame: PhysAddr::new(0),
            kernel_page_table: None,
            mapped_ranges: Vec::new(),
            next_free_addr: layout::VMAP_BASE,
            initialized: false,
        }
    }

    pub fn init(&mut self, cr3_frame: PhysAddr) -> VmResult<()> {
        if self.initialized {
            return Ok(());
        }

        self.cr3_frame = cr3_frame;
        self.kernel_page_table = Some(VirtAddr::new(layout::KERNEL_BASE + cr3_frame.as_u64()));
        self.mapped_ranges.clear();
        self.next_free_addr = layout::VMAP_BASE;
        self.initialized = true;

        Ok(())
    }

    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ========================================================================
    // PAGE MAPPING
    // ========================================================================
    pub fn map_page_4k(&mut self, va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> VmResult<()> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }

        self.validate_wx_permissions(flags)?;
        self.validate_alignment(va, pa, PageSize::Size4K)?;
        self.map_page_in_table(va, pa, flags, PageSize::Size4K)?;
        let range = MappedRange::new(va, pa, PAGE_SIZE_4K, flags, PageSize::Size4K);
        self.mapped_ranges.push(range);
        VM_STATS.record_mapping(PAGE_SIZE_4K);
        self.flush_tlb_single(va);

        Ok(())
    }

    /// Maps a 2M huge page.
    pub fn map_page_2m(&mut self, va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> VmResult<()> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }

        self.validate_wx_permissions(flags)?;
        self.validate_alignment(va, pa, PageSize::Size2M)?;
        self.map_page_in_table(va, pa, flags, PageSize::Size2M)?;
        let range = MappedRange::new(va, pa, PAGE_SIZE_2M, flags, PageSize::Size2M);
        self.mapped_ranges.push(range);
        VM_STATS.record_mapping(PAGE_SIZE_2M);
        self.flush_tlb_single(va);

        Ok(())
    }

    /// Unmaps a page.
    pub fn unmap_page(&mut self, va: VirtAddr, page_size: PageSize) -> VmResult<()> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }

        let range_idx = self
            .mapped_ranges
            .iter()
            .position(|r| r.start_va == va)
            .ok_or(VmError::AddressNotMapped)?;

        let range = self.mapped_ranges.remove(range_idx);
        self.unmap_page_in_table(va, page_size)?;
        VM_STATS.record_unmapping(range.size);
        self.flush_tlb_single(va);

        Ok(())
    }

    pub fn map_range(
        &mut self,
        va: VirtAddr,
        pa: PhysAddr,
        size: usize,
        flags: VmFlags,
    ) -> VmResult<()> {
        if size == 0 {
            return Err(VmError::InvalidRange);
        }

        let page_count = (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
        for i in 0..page_count {
            let page_va = VirtAddr::new(va.as_u64() + (i * PAGE_SIZE_4K) as u64);
            let page_pa = PhysAddr::new(pa.as_u64() + (i * PAGE_SIZE_4K) as u64);
            self.map_page_4k(page_va, page_pa, flags)?;
        }

        Ok(())
    }

    /// Unmaps a range of pages.
    pub fn unmap_range(&mut self, va: VirtAddr, size: usize) -> VmResult<()> {
        if size == 0 {
            return Err(VmError::InvalidRange);
        }

        let page_count = (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
        for i in 0..page_count {
            let page_va = VirtAddr::new(va.as_u64() + (i * PAGE_SIZE_4K) as u64);
            self.unmap_page(page_va, PageSize::Size4K)?;
        }

        Ok(())
    }

    // ========================================================================
    // TRANSLATION
    // ========================================================================
    pub fn translate(&self, va: VirtAddr) -> VmResult<(PhysAddr, VmFlags, usize)> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }

        if let Some(range) = self.find_mapped_range(va) {
            let offset = va.as_u64() - range.start_va.as_u64();
            let pa = PhysAddr::new(range.start_pa.as_u64() + offset);
            Ok((pa, range.flags, range.size))
        } else {
            Err(VmError::AddressNotMapped)
        }
    }

    pub fn find_mapped_range(&self, va: VirtAddr) -> Option<&MappedRange> {
        self.mapped_ranges.iter().find(|range| range.contains(va))
    }

    // ========================================================================
    // VALIDATION
    // ========================================================================
    fn validate_wx_permissions(&self, flags: VmFlags) -> VmResult<()> {
        let writable = flags.contains(VmFlags::Write);
        let executable = !flags.contains(VmFlags::NoExecute);
        if writable && executable {
            VM_STATS.record_wx_violation();
            return Err(VmError::WXViolation);
        }

        Ok(())
    }

    /// Validates address alignment for page size.
    fn validate_alignment(&self, va: VirtAddr, pa: PhysAddr, page_size: PageSize) -> VmResult<()> {
        if !page_size.is_aligned(va.as_u64()) || !page_size.is_aligned(pa.as_u64()) {
            return Err(VmError::InvalidAlignment);
        }
        Ok(())
    }

    // ========================================================================
    // PAGE TABLE OPERATIONS
    // ========================================================================
    fn map_page_in_table(
        &self,
        va: VirtAddr,
        pa: PhysAddr,
        flags: VmFlags,
        page_size: PageSize,
    ) -> VmResult<()> {
        let pte_flags =
            self.vm_flags_to_pte(flags) | if page_size == PageSize::Size2M { PTE_HUGE_PAGE } else { 0 };

        // SAFETY: Walking page tables with proper validation
        unsafe {
            self.walk_page_table(va, true, |pte_ptr| {
                *pte_ptr = pa.as_u64() | pte_flags;
                Ok(())
            })
        }
    }

    /// Unmaps a page from the page table.
    fn unmap_page_in_table(&self, va: VirtAddr, _page_size: PageSize) -> VmResult<()> {
        // SAFETY: Walking page tables with proper validation
        unsafe {
            self.walk_page_table(va, false, |pte_ptr| {
                *pte_ptr = 0;
                Ok(())
            })
        }
    }

    /// Walks the page table to find/create the PTE for a virtual address.
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - Exclusive access to page tables (via lock)
    /// - Valid kernel page table pointer
    unsafe fn walk_page_table<F>(
        &self,
        va: VirtAddr,
        create_tables: bool,
        mut callback: F,
    ) -> VmResult<()>
    where
        F: FnMut(*mut u64) -> VmResult<()>,
    {
        let l4_table = self
            .kernel_page_table
            .ok_or(VmError::NotInitialized)?
            .as_mut_ptr::<u64>();

        let l4_idx = l4_index(va.as_u64());
        let l3_idx = l3_index(va.as_u64());
        let l2_idx = l2_index(va.as_u64());
        let l1_idx = l1_index(va.as_u64());
        // SAFETY: l4_table is valid and l4_idx < 512
        let l4_entry = l4_table.add(l4_idx);
        if !pte_is_present(*l4_entry) {
            if !create_tables {
                return Err(VmError::AddressNotMapped);
            }
            let l3_frame = frame_alloc::allocate_frame().ok_or(VmError::OutOfMemory)?;
            // SAFETY: Writing to valid page table entry
            *l4_entry = l3_frame.as_u64() | PTE_PRESENT | PTE_WRITABLE;
        }

        // SAFETY: Entry is present, address is valid
        let l3_table = (pte_address(*l4_entry) + layout::KERNEL_BASE) as *mut u64;
        let l3_entry = l3_table.add(l3_idx);
        if !pte_is_present(*l3_entry) {
            if !create_tables {
                return Err(VmError::AddressNotMapped);
            }
            let l2_frame = frame_alloc::allocate_frame().ok_or(VmError::OutOfMemory)?;
            // SAFETY: Writing to valid page table entry
            *l3_entry = l2_frame.as_u64() | PTE_PRESENT | PTE_WRITABLE;
        }

        // SAFETY: Entry is present, address is valid
        let l2_table = (pte_address(*l3_entry) + layout::KERNEL_BASE) as *mut u64;
        let l2_entry = l2_table.add(l2_idx);
        if !pte_is_present(*l2_entry) {
            if !create_tables {
                return Err(VmError::AddressNotMapped);
            }
            let l1_frame = frame_alloc::allocate_frame().ok_or(VmError::OutOfMemory)?;
            // SAFETY: Writing to valid page table entry
            *l2_entry = l1_frame.as_u64() | PTE_PRESENT | PTE_WRITABLE;
        }

        // SAFETY: Entry is present, address is valid
        let l1_table = (pte_address(*l2_entry) + layout::KERNEL_BASE) as *mut u64;
        let l1_entry = l1_table.add(l1_idx);

        callback(l1_entry)
    }

    /// Converts VmFlags to PTE flags.
    fn vm_flags_to_pte(&self, flags: VmFlags) -> u64 {
        let mut pte_flags = 0u64;

        if flags.contains(VmFlags::Present) {
            pte_flags |= PTE_PRESENT;
        }
        if flags.contains(VmFlags::Write) {
            pte_flags |= PTE_WRITABLE;
        }
        if flags.contains(VmFlags::User) {
            pte_flags |= PTE_USER;
        }
        if flags.contains(VmFlags::WriteThrough) {
            pte_flags |= PTE_WRITE_THROUGH;
        }
        if flags.contains(VmFlags::CacheDisable) {
            pte_flags |= PTE_CACHE_DISABLE;
        }
        if flags.contains(VmFlags::Global) {
            pte_flags |= PTE_GLOBAL;
        }
        if flags.contains(VmFlags::NoExecute) {
            pte_flags |= PTE_NO_EXECUTE;
        }

        pte_flags
    }

    // ========================================================================
    // TLB OPERATIONS
    // ========================================================================
    pub fn flush_tlb_single(&self, va: VirtAddr) {
        // SAFETY: INVLPG is always safe to execute
        unsafe {
            core::arch::asm!(
                "invlpg [{}]",
                in(reg) va.as_u64(),
                options(nostack, preserves_flags)
            );
        }
        VM_STATS.record_tlb_flush();
    }

    /// Flushes the entire TLB.
    pub fn flush_tlb_all(&self) {
        // SAFETY: Writing CR3 to itself flushes TLB
        unsafe {
            let cr3 = Cr3::read().0;
            Cr3::write(cr3, Cr3Flags::empty());
        }
        VM_STATS.record_tlb_flush();
    }
}

impl Default for VirtualMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

// Public API
use spin::Mutex;
use super::types::VmStatsSnapshot;
static VIRTUAL_MEMORY_MANAGER: Mutex<VirtualMemoryManager> = Mutex::new(VirtualMemoryManager::new());
pub fn init(cr3_frame: PhysAddr) -> VmResult<()> { VIRTUAL_MEMORY_MANAGER.lock().init(cr3_frame) }
pub fn map_page_4k(va: VirtAddr, pa: PhysAddr, writable: bool, user: bool, executable: bool) -> VmResult<()> {
    let flags = build_flags(writable, user, executable);
    VIRTUAL_MEMORY_MANAGER.lock().map_page_4k(va, pa, flags)
}

pub fn map_page_2m(va: VirtAddr, pa: PhysAddr, writable: bool, user: bool, executable: bool) -> VmResult<()> {
    let flags = build_flags(writable, user, executable);
    VIRTUAL_MEMORY_MANAGER.lock().map_page_2m(va, pa, flags)
}

pub fn unmap_page(va: VirtAddr) -> VmResult<()> {
    VIRTUAL_MEMORY_MANAGER.lock().unmap_page(va, PageSize::Size4K)
}

pub fn unmap_page_2m(va: VirtAddr) -> VmResult<()> {
    VIRTUAL_MEMORY_MANAGER.lock().unmap_page(va, PageSize::Size2M)
}

pub fn map_range(va: VirtAddr, pa: PhysAddr, size: usize, writable: bool, user: bool, executable: bool) -> VmResult<()> {
    let flags = build_flags(writable, user, executable);
    VIRTUAL_MEMORY_MANAGER.lock().map_range(va, pa, size, flags)
}

pub fn unmap_range(va: VirtAddr, size: usize) -> VmResult<()> {
    VIRTUAL_MEMORY_MANAGER.lock().unmap_range(va, size)
}

pub fn translate_addr(va: VirtAddr) -> VmResult<PhysAddr> {
    let (pa, _, _) = VIRTUAL_MEMORY_MANAGER.lock().translate(va)?;
    Ok(pa)
}

pub fn translate_with_flags(va: VirtAddr) -> VmResult<(PhysAddr, VmFlags, usize)> {
    VIRTUAL_MEMORY_MANAGER.lock().translate(va)
}

pub fn flush_tlb() { VIRTUAL_MEMORY_MANAGER.lock().flush_tlb_all(); }
pub fn flush_tlb_page(va: VirtAddr) { VIRTUAL_MEMORY_MANAGER.lock().flush_tlb_single(va); }
pub fn is_mapped(va: VirtAddr) -> bool {
    VIRTUAL_MEMORY_MANAGER.lock().find_mapped_range(va).is_some()
}

pub fn validate_range(va: VirtAddr, size: usize, required_flags: VmFlags) -> bool {
    let manager = VIRTUAL_MEMORY_MANAGER.lock();
    let page_count = (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
    for i in 0..page_count {
        let page_va = VirtAddr::new(va.as_u64() + (i * PAGE_SIZE_4K) as u64);
        if let Some(range) = manager.find_mapped_range(page_va) {
            if !range.flags.contains(required_flags) { return false; }
        } else { return false; }
    }
    true
}

pub fn handle_page_fault(va: VirtAddr, error_code: u64) -> VmResult<()> {
    VM_STATS.record_page_fault();
    let present = (error_code & PF_PRESENT) != 0;
    let write = (error_code & PF_WRITE) != 0;
    if !present { return Err(VmError::AddressNotMapped); }
    if write { return Err(VmError::PermissionViolation); }
    Ok(())
}

pub fn get_stats() -> VmStatsSnapshot { VM_STATS.snapshot() }
pub fn is_kpti_enabled() -> bool {
    let cr4: u64;
    // SAFETY: Reading CR4 is always safe
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)); }
    (cr4 & CR4_PCIDE) != 0
}

fn build_flags(writable: bool, user: bool, executable: bool) -> VmFlags {
    let mut flags = VmFlags::Present;
    if writable { flags = flags | VmFlags::Write; }
    if user { flags = flags | VmFlags::User; }
    if !executable { flags = flags | VmFlags::NoExecute; }
    flags
}
