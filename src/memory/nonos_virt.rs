#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr, registers::control::{Cr3, Cr3Flags}};
use crate::memory::nonos_layout as layout;
use crate::memory::nonos_frame_alloc as frame_alloc;
use crate::memory::nonos_proof as proof;

static VIRTUAL_MEMORY_MANAGER: Mutex<VirtualMemoryManager> = Mutex::new(VirtualMemoryManager::new());
static VM_STATS: VmStats = VmStats::new();

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmFlags {
    None = 0,
    Present = 1 << 0,
    Write = 1 << 1,
    User = 1 << 2,
    WriteThrough = 1 << 3,
    CacheDisable = 1 << 4,
    Global = 1 << 8,
    NoExecute = 1 << 63,
}

impl VmFlags {
    pub const READ: VmFlags = VmFlags::Present;
    pub const RW: VmFlags = VmFlags::Write;  // For backwards compatibility
    pub const READ_WRITE: VmFlags = VmFlags::Present;  // Combined via |
    pub const NX: VmFlags = VmFlags::NoExecute;
    pub const PWT: VmFlags = VmFlags::WriteThrough;
    pub const PCD: VmFlags = VmFlags::CacheDisable;
    pub const GLOBAL: VmFlags = VmFlags::Global;
    pub const USER: VmFlags = VmFlags::User;

    pub const fn contains(self, other: VmFlags) -> bool {
        (self as u64) & (other as u64) != 0
    }

    pub const fn bits(self) -> u64 {
        self as u64
    }
}

impl core::ops::BitOr for VmFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        unsafe { core::mem::transmute((self as u64) | (rhs as u64)) }
    }
}

impl core::ops::BitOrAssign for VmFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VmError {
    NotInitialized,
    OutOfMemory,
    InvalidAlignment,
    AddressNotMapped,
    PermissionViolation,
    InvalidRange,
    PageTableError,
}

struct VirtualMemoryManager {
    cr3_frame: PhysAddr,
    kernel_page_table: Option<VirtAddr>,
    mapped_ranges: Vec<MappedRange>,
    next_free_addr: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy)]
struct MappedRange {
    start_va: VirtAddr,
    start_pa: PhysAddr,
    size: usize,
    flags: VmFlags,
    page_size: PageSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageSize {
    Size4K = 4096,
    Size2M = 2 * 1024 * 1024,
    Size1G = 1024 * 1024 * 1024,
}

struct VmStats {
    mapped_pages: AtomicUsize,
    mapped_memory: AtomicU64,
    page_faults: AtomicU64,
    tlb_flushes: AtomicU64,
    wx_violations: AtomicU64,
}

impl VmStats {
    const fn new() -> Self {
        Self {
            mapped_pages: AtomicUsize::new(0),
            mapped_memory: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
            tlb_flushes: AtomicU64::new(0),
            wx_violations: AtomicU64::new(0),
        }
    }

    fn record_mapping(&self, size: usize) {
        let pages = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        self.mapped_pages.fetch_add(pages, Ordering::Relaxed);
        self.mapped_memory.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn record_unmapping(&self, size: usize) {
        let pages = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        self.mapped_pages.fetch_sub(pages, Ordering::Relaxed);
        self.mapped_memory.fetch_sub(size as u64, Ordering::Relaxed);
    }

    fn record_page_fault(&self) {
        self.page_faults.fetch_add(1, Ordering::Relaxed);
    }

    fn record_tlb_flush(&self) {
        self.tlb_flushes.fetch_add(1, Ordering::Relaxed);
    }

    fn record_wx_violation(&self) {
        self.wx_violations.fetch_add(1, Ordering::Relaxed);
    }
}

impl VirtualMemoryManager {
    const fn new() -> Self {
        Self {
            cr3_frame: PhysAddr::new(0),
            kernel_page_table: None,
            mapped_ranges: Vec::new(),
            next_free_addr: layout::VMAP_BASE,
            initialized: false,
        }
    }

    fn init(&mut self, cr3_frame: PhysAddr) -> Result<(), VmError> {
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

    fn map_page_4k(&mut self, va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> Result<(), VmError> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }

        self.validate_wx_permissions(flags)?;
        self.validate_alignment_4k(va, pa)?;

        self.map_page_in_table(va, pa, flags, PageSize::Size4K)?;
        
        let range = MappedRange {
            start_va: va,
            start_pa: pa,
            size: layout::PAGE_SIZE,
            flags,
            page_size: PageSize::Size4K,
        };
        self.mapped_ranges.push(range);

        VM_STATS.record_mapping(layout::PAGE_SIZE);
        self.flush_tlb_single(va);

        Ok(())
    }

    fn map_page_2m(&mut self, va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> Result<(), VmError> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }

        self.validate_wx_permissions(flags)?;
        self.validate_alignment_2m(va, pa)?;

        self.map_page_in_table(va, pa, flags, PageSize::Size2M)?;

        let range = MappedRange {
            start_va: va,
            start_pa: pa,
            size: PageSize::Size2M as usize,
            flags,
            page_size: PageSize::Size2M,
        };
        self.mapped_ranges.push(range);

        VM_STATS.record_mapping(PageSize::Size2M as usize);
        self.flush_tlb_single(va);

        Ok(())
    }

    fn unmap_page(&mut self, va: VirtAddr, page_size: PageSize) -> Result<(), VmError> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }

        let range_idx = self.mapped_ranges.iter().position(|r| r.start_va == va)
            .ok_or(VmError::AddressNotMapped)?;

        let range = self.mapped_ranges.remove(range_idx);

        self.unmap_page_in_table(va, page_size)?;

        VM_STATS.record_unmapping(range.size);
        self.flush_tlb_single(va);

        Ok(())
    }

    fn map_range(&mut self, va: VirtAddr, pa: PhysAddr, size: usize, flags: VmFlags) -> Result<(), VmError> {
        if size == 0 {
            return Err(VmError::InvalidRange);
        }

        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;

        for i in 0..page_count {
            let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
            let page_pa = PhysAddr::new(pa.as_u64() + (i * layout::PAGE_SIZE) as u64);
            self.map_page_4k(page_va, page_pa, flags)?;
        }

        Ok(())
    }

    fn unmap_range(&mut self, va: VirtAddr, size: usize) -> Result<(), VmError> {
        if size == 0 {
            return Err(VmError::InvalidRange);
        }

        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;

        for i in 0..page_count {
            let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
            self.unmap_page(page_va, PageSize::Size4K)?;
        }

        Ok(())
    }

    fn translate(&self, va: VirtAddr) -> Result<(PhysAddr, VmFlags, usize), VmError> {
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

    fn find_mapped_range(&self, va: VirtAddr) -> Option<&MappedRange> {
        self.mapped_ranges.iter().find(|range| {
            let start = range.start_va.as_u64();
            let end = start + range.size as u64;
            va.as_u64() >= start && va.as_u64() < end
        })
    }

    fn validate_wx_permissions(&self, flags: VmFlags) -> Result<(), VmError> {
        let writable = flags.contains(VmFlags::Write);
        let executable = !flags.contains(VmFlags::NoExecute);

        if writable && executable {
            VM_STATS.record_wx_violation();
            return Err(VmError::PermissionViolation);
        }

        Ok(())
    }

    fn validate_alignment_4k(&self, va: VirtAddr, pa: PhysAddr) -> Result<(), VmError> {
        if va.as_u64() % layout::PAGE_SIZE as u64 != 0 || pa.as_u64() % layout::PAGE_SIZE as u64 != 0 {
            return Err(VmError::InvalidAlignment);
        }
        Ok(())
    }

    fn validate_alignment_2m(&self, va: VirtAddr, pa: PhysAddr) -> Result<(), VmError> {
        const ALIGN_2M: u64 = 2 * 1024 * 1024;
        if va.as_u64() % ALIGN_2M != 0 || pa.as_u64() % ALIGN_2M != 0 {
            return Err(VmError::InvalidAlignment);
        }
        Ok(())
    }

    fn map_page_in_table(&self, va: VirtAddr, pa: PhysAddr, flags: VmFlags, page_size: PageSize) -> Result<(), VmError> {
        let pte_flags = self.vm_flags_to_pte_flags(flags) | if page_size == PageSize::Size2M { 0x80 } else { 0 };
        
        unsafe {
            self.walk_page_table(va, true, |pte_ptr| {
                *pte_ptr = pa.as_u64() | pte_flags;
                Ok(())
            })
        }
    }

    fn unmap_page_in_table(&self, va: VirtAddr, _page_size: PageSize) -> Result<(), VmError> {
        unsafe {
            self.walk_page_table(va, false, |pte_ptr| {
                *pte_ptr = 0;
                Ok(())
            })
        }
    }

    unsafe fn walk_page_table<F>(&self, va: VirtAddr, create_tables: bool, mut callback: F) -> Result<(), VmError>
    where
        F: FnMut(*mut u64) -> Result<(), VmError>,
    {
        let l4_table = self.kernel_page_table.ok_or(VmError::NotInitialized)?.as_mut_ptr::<u64>();

        let l4_idx = (va.as_u64() >> 39) & 0x1FF;
        let l3_idx = (va.as_u64() >> 30) & 0x1FF;
        let l2_idx = (va.as_u64() >> 21) & 0x1FF;
        let l1_idx = (va.as_u64() >> 12) & 0x1FF;

        let l4_entry = l4_table.add(l4_idx as usize);
        if *l4_entry & 1 == 0 {
            if !create_tables {
                return Err(VmError::AddressNotMapped);
            }
            let l3_frame = frame_alloc::allocate_frame().ok_or(VmError::OutOfMemory)?;
            *l4_entry = l3_frame.as_u64() | 0x03;
        }

        let l3_table = ((*l4_entry & !0xFFF) + layout::KERNEL_BASE) as *mut u64;
        let l3_entry = l3_table.add(l3_idx as usize);
        if *l3_entry & 1 == 0 {
            if !create_tables {
                return Err(VmError::AddressNotMapped);
            }
            let l2_frame = frame_alloc::allocate_frame().ok_or(VmError::OutOfMemory)?;
            *l3_entry = l2_frame.as_u64() | 0x03;
        }

        let l2_table = ((*l3_entry & !0xFFF) + layout::KERNEL_BASE) as *mut u64;
        let l2_entry = l2_table.add(l2_idx as usize);
        if *l2_entry & 1 == 0 {
            if !create_tables {
                return Err(VmError::AddressNotMapped);
            }
            let l1_frame = frame_alloc::allocate_frame().ok_or(VmError::OutOfMemory)?;
            *l2_entry = l1_frame.as_u64() | 0x03;
        }

        let l1_table = ((*l2_entry & !0xFFF) + layout::KERNEL_BASE) as *mut u64;
        let l1_entry = l1_table.add(l1_idx as usize);

        callback(l1_entry)
    }

    fn vm_flags_to_pte_flags(&self, flags: VmFlags) -> u64 {
        let mut pte_flags = 0u64;

        if flags.contains(VmFlags::Present) {
            pte_flags |= 0x01;
        }
        if flags.contains(VmFlags::Write) {
            pte_flags |= 0x02;
        }
        if flags.contains(VmFlags::User) {
            pte_flags |= 0x04;
        }
        if flags.contains(VmFlags::WriteThrough) {
            pte_flags |= 0x08;
        }
        if flags.contains(VmFlags::CacheDisable) {
            pte_flags |= 0x10;
        }
        if flags.contains(VmFlags::Global) {
            pte_flags |= 0x100;
        }
        if flags.contains(VmFlags::NoExecute) {
            pte_flags |= 1u64 << 63;
        }

        pte_flags
    }

    fn flush_tlb_single(&self, va: VirtAddr) {
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) va.as_u64(), options(nostack, preserves_flags));
        }
        VM_STATS.record_tlb_flush();
    }

    fn flush_tlb_all(&self) {
        unsafe {
            let cr3 = Cr3::read().0;
            Cr3::write(cr3, Cr3Flags::empty());
        }
        VM_STATS.record_tlb_flush();
    }
}

pub fn init(cr3_frame: PhysAddr) -> Result<(), VmError> {
    let mut manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.init(cr3_frame)
}

pub fn map_page_4k(va: VirtAddr, pa: PhysAddr, writable: bool, user: bool, executable: bool) -> Result<(), VmError> {
    let mut flags = VmFlags::Present;
    if writable {
        flags = flags | VmFlags::Write;
    }
    if user {
        flags = flags | VmFlags::User;
    }
    if !executable {
        flags = flags | VmFlags::NoExecute;
    }

    let mut manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.map_page_4k(va, pa, flags)
}

pub fn map_page_2m(va: VirtAddr, pa: PhysAddr, writable: bool, user: bool, executable: bool) -> Result<(), VmError> {
    let mut flags = VmFlags::Present;
    if writable {
        flags = flags | VmFlags::Write;
    }
    if user {
        flags = flags | VmFlags::User;
    }
    if !executable {
        flags = flags | VmFlags::NoExecute;
    }

    let mut manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.map_page_2m(va, pa, flags)
}

pub fn unmap_page(va: VirtAddr) -> Result<(), VmError> {
    let mut manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.unmap_page(va, PageSize::Size4K)
}

pub fn unmap_page_2m(va: VirtAddr) -> Result<(), VmError> {
    let mut manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.unmap_page(va, PageSize::Size2M)
}

pub fn map_range(va: VirtAddr, pa: PhysAddr, size: usize, writable: bool, user: bool, executable: bool) -> Result<(), VmError> {
    let mut flags = VmFlags::Present;
    if writable {
        flags = flags | VmFlags::Write;
    }
    if user {
        flags = flags | VmFlags::User;
    }
    if !executable {
        flags = flags | VmFlags::NoExecute;
    }

    let mut manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.map_range(va, pa, size, flags)
}

pub fn unmap_range(va: VirtAddr, size: usize) -> Result<(), VmError> {
    let mut manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.unmap_range(va, size)
}

pub fn translate_addr(va: VirtAddr) -> Result<PhysAddr, VmError> {
    let manager = VIRTUAL_MEMORY_MANAGER.lock();
    let (pa, _, _) = manager.translate(va)?;
    Ok(pa)
}

pub fn translate_with_flags(va: VirtAddr) -> Result<(PhysAddr, VmFlags, usize), VmError> {
    let manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.translate(va)
}

pub fn flush_tlb() {
    let manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.flush_tlb_all();
}

pub fn flush_tlb_page(va: VirtAddr) {
    let manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.flush_tlb_single(va);
}

pub fn handle_page_fault(va: VirtAddr, error_code: u64) -> Result<(), VmError> {
    VM_STATS.record_page_fault();

    let present = (error_code & 0x1) != 0;
    let write = (error_code & 0x2) != 0;
    let user = (error_code & 0x4) != 0;

    if !present {
        return Err(VmError::AddressNotMapped);
    }

    if write {
        return Err(VmError::PermissionViolation);
    }

    Ok(())
}

pub fn get_stats() -> VmStatsSnapshot {
    VmStatsSnapshot {
        mapped_pages: VM_STATS.mapped_pages.load(Ordering::Relaxed),
        mapped_memory: VM_STATS.mapped_memory.load(Ordering::Relaxed),
        page_faults: VM_STATS.page_faults.load(Ordering::Relaxed),
        tlb_flushes: VM_STATS.tlb_flushes.load(Ordering::Relaxed),
        wx_violations: VM_STATS.wx_violations.load(Ordering::Relaxed),
    }
}

#[derive(Debug)]
pub struct VmStatsSnapshot {
    pub mapped_pages: usize,
    pub mapped_memory: u64,
    pub page_faults: u64,
    pub tlb_flushes: u64,
    pub wx_violations: u64,
}

pub fn is_mapped(va: VirtAddr) -> bool {
    let manager = VIRTUAL_MEMORY_MANAGER.lock();
    manager.find_mapped_range(va).is_some()
}

pub fn validate_range(va: VirtAddr, size: usize, required_flags: VmFlags) -> bool {
    let manager = VIRTUAL_MEMORY_MANAGER.lock();
    
    let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    
    for i in 0..page_count {
        let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
        
        if let Some(range) = manager.find_mapped_range(page_va) {
            if !range.flags.contains(required_flags) {
                return false;
            }
        } else {
            return false;
        }
    }
    
    true
}