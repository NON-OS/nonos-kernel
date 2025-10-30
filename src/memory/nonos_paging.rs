#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr, registers::control::{Cr3, Cr3Flags}};
use crate::memory::{
    nonos_layout as layout,
    nonos_frame_alloc as frame_alloc,
    nonos_page_info as page_info,
};

static PAGING_MANAGER: Mutex<PagingManager> = Mutex::new(PagingManager::new());
static PAGING_STATS: PagingStatistics = PagingStatistics::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePermissions {
    bits: u32,
}

impl PagePermissions {
    pub const READ: Self = Self { bits: 1 << 0 };
    pub const WRITE: Self = Self { bits: 1 << 1 };
    pub const EXECUTE: Self = Self { bits: 1 << 2 };
    pub const USER: Self = Self { bits: 1 << 3 };
    pub const GLOBAL: Self = Self { bits: 1 << 4 };
    pub const NO_CACHE: Self = Self { bits: 1 << 5 };
    pub const WRITE_THROUGH: Self = Self { bits: 1 << 6 };
    pub const COW: Self = Self { bits: 1 << 7 };
    pub const DEMAND: Self = Self { bits: 1 << 8 };
    pub const ZERO_FILL: Self = Self { bits: 1 << 9 };
    pub const SHARED: Self = Self { bits: 1 << 10 };
    pub const LOCKED: Self = Self { bits: 1 << 11 };
    pub const DEVICE: Self = Self { bits: 1 << 12 };

    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub const fn union(self, other: Self) -> Self {
        Self { bits: self.bits | other.bits }
    }

    pub const fn remove(self, other: Self) -> Self {
        Self { bits: self.bits & !other.bits }
    }

    pub const fn insert(self, other: Self) -> Self {
        self.union(other)
    }
}

impl core::ops::BitOr for PagePermissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for PagePermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    Size4KiB,
    Size2MiB,
    Size1GiB,
}

#[derive(Debug, Clone)]
pub struct PageMapping {
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub size: PageSize,
    pub permissions: PagePermissions,
    pub process_id: Option<u32>,
    pub reference_count: u32,
    pub creation_time: u64,
    pub last_accessed: u64,
}

struct PagingManager {
    active_page_table: Option<PhysAddr>,
    mappings: BTreeMap<u64, PageMapping>,
    address_spaces: BTreeMap<u32, AddressSpace>,
    next_asid: u32,
    initialized: bool,
}

#[derive(Debug, Clone)]
struct AddressSpace {
    asid: u32,
    cr3_value: PhysAddr,
    mappings: Vec<VirtAddr>,
    process_id: u32,
    creation_time: u64,
}

struct PagingStatistics {
    total_mappings: AtomicUsize,
    page_faults: AtomicU64,
    tlb_flushes: AtomicU64,
    cow_faults: AtomicU64,
    demand_loads: AtomicU64,
    huge_pages: AtomicUsize,
    user_pages: AtomicUsize,
    kernel_pages: AtomicUsize,
}

impl PagingStatistics {
    const fn new() -> Self {
        Self {
            total_mappings: AtomicUsize::new(0),
            page_faults: AtomicU64::new(0),
            tlb_flushes: AtomicU64::new(0),
            cow_faults: AtomicU64::new(0),
            demand_loads: AtomicU64::new(0),
            huge_pages: AtomicUsize::new(0),
            user_pages: AtomicUsize::new(0),
            kernel_pages: AtomicUsize::new(0),
        }
    }
    
    fn record_mapping(&self, permissions: PagePermissions, size: PageSize) {
        self.total_mappings.fetch_add(1, Ordering::Relaxed);
        
        if permissions.contains(PagePermissions::USER) {
            self.user_pages.fetch_add(1, Ordering::Relaxed);
        } else {
            self.kernel_pages.fetch_add(1, Ordering::Relaxed);
        }
        
        if matches!(size, PageSize::Size2MiB | PageSize::Size1GiB) {
            self.huge_pages.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    fn record_unmapping(&self, permissions: PagePermissions, size: PageSize) {
        self.total_mappings.fetch_sub(1, Ordering::Relaxed);
        
        if permissions.contains(PagePermissions::USER) {
            self.user_pages.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.kernel_pages.fetch_sub(1, Ordering::Relaxed);
        }
        
        if matches!(size, PageSize::Size2MiB | PageSize::Size1GiB) {
            self.huge_pages.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl PagingManager {
    const fn new() -> Self {
        Self {
            active_page_table: None,
            mappings: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            next_asid: 1,
            initialized: false,
        }
    }
    
    fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }
        
        let (cr3_frame, _) = Cr3::read();
        self.active_page_table = Some(cr3_frame.start_address());
        self.initialized = true;
        
        self.create_kernel_address_space()?;
        Ok(())
    }
    
    fn create_kernel_address_space(&mut self) -> Result<(), &'static str> {
        let cr3_value = self.active_page_table.ok_or("No active page table")?;
        let kernel_space = AddressSpace {
            asid: 0,
            cr3_value,
            mappings: Vec::new(),
            process_id: 0,
            creation_time: get_timestamp(),
        };
        
        self.address_spaces.insert(0, kernel_space);
        Ok(())
    }
    
    fn create_address_space(&mut self, process_id: u32) -> Result<u32, &'static str> {
        let asid = self.next_asid;
        self.next_asid += 1;
        
        let page_table_frame = frame_alloc::allocate_frame()
            .ok_or("Failed to allocate page table frame")?;
        
        let page_table_pa = page_table_frame;
        
        let address_space = AddressSpace {
            asid,
            cr3_value: page_table_pa,
            mappings: Vec::new(),
            process_id,
            creation_time: get_timestamp(),
        };
        
        self.address_spaces.insert(asid, address_space);
        self.initialize_address_space(page_table_pa)?;
        
        Ok(asid)
    }
    
    fn initialize_address_space(&self, page_table_pa: PhysAddr) -> Result<(), &'static str> {
        let page_table_va = layout::DIRECTMAP_BASE + page_table_pa.as_u64();
        let page_table = unsafe { &mut *(page_table_va as *mut [u64; 512]) };
        
        for entry in page_table.iter_mut() {
            *entry = 0;
        }
        
        if let Some(kernel_cr3) = self.active_page_table {
            let kernel_table_va = layout::DIRECTMAP_BASE + kernel_cr3.as_u64();
            let kernel_table = unsafe { &*(kernel_table_va as *const [u64; 512]) };
            
            for i in 256..512 {
                page_table[i] = kernel_table[i];
            }
        }
        
        Ok(())
    }
    
    fn map_page(&mut self, virtual_addr: VirtAddr, physical_addr: PhysAddr, 
                permissions: PagePermissions, size: PageSize) -> Result<(), &'static str> {
        if !self.initialized {
            return Err("Paging manager not initialized");
        }
        
        let mut pte_flags = 1u64;
        
        if permissions.contains(PagePermissions::WRITE) {
            pte_flags |= 2;
        }
        if permissions.contains(PagePermissions::USER) {
            pte_flags |= 4;
        }
        if permissions.contains(PagePermissions::WRITE_THROUGH) {
            pte_flags |= 8;
        }
        if permissions.contains(PagePermissions::NO_CACHE) {
            pte_flags |= 16;
        }
        if permissions.contains(PagePermissions::GLOBAL) {
            pte_flags |= 256;
        }
        if !permissions.contains(PagePermissions::EXECUTE) {
            pte_flags |= 1u64 << 63;
        }
        
        self.install_mapping(virtual_addr, physical_addr, pte_flags)?;
        
        let mapping = PageMapping {
            virtual_addr,
            physical_addr,
            size,
            permissions,
            process_id: None,
            reference_count: 1,
            creation_time: get_timestamp(),
            last_accessed: get_timestamp(),
        };
        
        let page_addr = virtual_addr.as_u64() & layout::PAGE_MASK;
        self.mappings.insert(page_addr, mapping);
        
        PAGING_STATS.record_mapping(permissions, size);
        
        Ok(())
    }
    
    fn install_mapping(&self, va: VirtAddr, pa: PhysAddr, flags: u64) -> Result<(), &'static str> {
        let va_val = va.as_u64();
        let l4_idx = (va_val >> 39) & 0x1FF;
        let l3_idx = (va_val >> 30) & 0x1FF;
        let l2_idx = (va_val >> 21) & 0x1FF;
        let l1_idx = (va_val >> 12) & 0x1FF;
        
        let cr3 = self.active_page_table.ok_or("No active page table")?;
        let l4_table = unsafe { &mut *((layout::DIRECTMAP_BASE + cr3.as_u64()) as *mut [u64; 512]) };
        
        if l4_table[l4_idx as usize] & 1 == 0 {
            let new_table = frame_alloc::allocate_frame().ok_or("Failed to allocate L3 table")?;
            l4_table[l4_idx as usize] = new_table.as_u64() | 0x7;
            let table_va = layout::DIRECTMAP_BASE + new_table.as_u64();
            unsafe { core::ptr::write_bytes(table_va as *mut u8, 0, 4096); }
        }
        
        let l3_pa = PhysAddr::new(l4_table[l4_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l3_table = unsafe { &mut *((layout::DIRECTMAP_BASE + l3_pa.as_u64()) as *mut [u64; 512]) };
        
        if l3_table[l3_idx as usize] & 1 == 0 {
            let new_table = frame_alloc::allocate_frame().ok_or("Failed to allocate L2 table")?;
            l3_table[l3_idx as usize] = new_table.as_u64() | 0x7;
            let table_va = layout::DIRECTMAP_BASE + new_table.as_u64();
            unsafe { core::ptr::write_bytes(table_va as *mut u8, 0, 4096); }
        }
        
        let l2_pa = PhysAddr::new(l3_table[l3_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l2_table = unsafe { &mut *((layout::DIRECTMAP_BASE + l2_pa.as_u64()) as *mut [u64; 512]) };
        
        if l2_table[l2_idx as usize] & 1 == 0 {
            let new_table = frame_alloc::allocate_frame().ok_or("Failed to allocate L1 table")?;
            l2_table[l2_idx as usize] = new_table.as_u64() | 0x7;
            let table_va = layout::DIRECTMAP_BASE + new_table.as_u64();
            unsafe { core::ptr::write_bytes(table_va as *mut u8, 0, 4096); }
        }
        
        let l1_pa = PhysAddr::new(l2_table[l2_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l1_table = unsafe { &mut *((layout::DIRECTMAP_BASE + l1_pa.as_u64()) as *mut [u64; 512]) };
        
        l1_table[l1_idx as usize] = pa.as_u64() | flags;
        
        self.flush_tlb(Some(va));
        
        Ok(())
    }
    
    fn unmap_page(&mut self, virtual_addr: VirtAddr) -> Result<PhysAddr, &'static str> {
        if !self.initialized {
            return Err("Paging manager not initialized");
        }
        
        let page_addr = virtual_addr.as_u64() & layout::PAGE_MASK;
        
        let mapping = self.mappings.remove(&page_addr)
            .ok_or("Page not mapped")?;
        
        let physical_addr = self.remove_mapping(virtual_addr)?;
        
        PAGING_STATS.record_unmapping(mapping.permissions, mapping.size);
        
        Ok(physical_addr)
    }
    
    fn remove_mapping(&self, va: VirtAddr) -> Result<PhysAddr, &'static str> {
        let va_val = va.as_u64();
        let l4_idx = (va_val >> 39) & 0x1FF;
        let l3_idx = (va_val >> 30) & 0x1FF;
        let l2_idx = (va_val >> 21) & 0x1FF;
        let l1_idx = (va_val >> 12) & 0x1FF;
        
        let cr3 = self.active_page_table.ok_or("No active page table")?;
        let l4_table = unsafe { &*((layout::DIRECTMAP_BASE + cr3.as_u64()) as *const [u64; 512]) };
        
        if l4_table[l4_idx as usize] & 1 == 0 {
            return Err("L4 entry not present");
        }
        
        let l3_pa = PhysAddr::new(l4_table[l4_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l3_table = unsafe { &*((layout::DIRECTMAP_BASE + l3_pa.as_u64()) as *const [u64; 512]) };
        
        if l3_table[l3_idx as usize] & 1 == 0 {
            return Err("L3 entry not present");
        }
        
        let l2_pa = PhysAddr::new(l3_table[l3_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l2_table = unsafe { &*((layout::DIRECTMAP_BASE + l2_pa.as_u64()) as *const [u64; 512]) };
        
        if l2_table[l2_idx as usize] & 1 == 0 {
            return Err("L2 entry not present");
        }
        
        let l1_pa = PhysAddr::new(l2_table[l2_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l1_table = unsafe { &mut *((layout::DIRECTMAP_BASE + l1_pa.as_u64()) as *mut [u64; 512]) };
        
        if l1_table[l1_idx as usize] & 1 == 0 {
            return Err("Page not present");
        }
        
        let physical_addr = PhysAddr::new(l1_table[l1_idx as usize] & 0x000F_FFFF_FFFF_F000);
        l1_table[l1_idx as usize] = 0;
        
        self.flush_tlb(Some(va));
        
        Ok(physical_addr)
    }
    
    fn handle_page_fault(&mut self, virtual_addr: VirtAddr, error_code: u64) -> Result<(), &'static str> {
        PAGING_STATS.page_faults.fetch_add(1, Ordering::Relaxed);
        
        if error_code & 0x02 != 0 {
            PAGING_STATS.cow_faults.fetch_add(1, Ordering::Relaxed);
            return self.handle_cow_fault(virtual_addr);
        }
        
        if error_code & 0x01 == 0 {
            PAGING_STATS.demand_loads.fetch_add(1, Ordering::Relaxed);
            return self.handle_demand_fault(virtual_addr);
        }
        
        Err("Unhandled page fault")
    }
    
    fn handle_cow_fault(&mut self, virtual_addr: VirtAddr) -> Result<(), &'static str> {
        let new_frame = frame_alloc::allocate_frame()
            .ok_or("Failed to allocate frame for COW")?;
        
        if let Ok(original_pa) = self.translate_address(virtual_addr) {
            unsafe {
                let src_va = layout::DIRECTMAP_BASE + original_pa.as_u64();
                let dst_va = layout::DIRECTMAP_BASE + new_frame.as_u64();
                core::ptr::copy_nonoverlapping(
                    src_va as *const u8,
                    dst_va as *mut u8,
                    layout::PAGE_SIZE
                );
            }
        }
        
        let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::USER;
        self.map_page(virtual_addr, new_frame, permissions, PageSize::Size4KiB)?;
        
        Ok(())
    }
    
    fn handle_demand_fault(&mut self, virtual_addr: VirtAddr) -> Result<(), &'static str> {
        let new_frame = frame_alloc::allocate_frame()
            .ok_or("Failed to allocate frame for demand fault")?;
        
        unsafe {
            let va = layout::DIRECTMAP_BASE + new_frame.as_u64();
            core::ptr::write_bytes(va as *mut u8, 0, layout::PAGE_SIZE);
        }
        
        let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::USER;
        self.map_page(virtual_addr, new_frame, permissions, PageSize::Size4KiB)?;
        
        Ok(())
    }
    
    fn switch_address_space(&mut self, asid: u32) -> Result<(), &'static str> {
        let address_space = self.address_spaces.get(&asid)
            .ok_or("Address space not found")?;
        
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
    
    fn flush_tlb(&self, virtual_addr: Option<VirtAddr>) -> Result<(), &'static str> {
        PAGING_STATS.tlb_flushes.fetch_add(1, Ordering::Relaxed);
        
        match virtual_addr {
            Some(addr) => {
                unsafe {
                    core::arch::asm!("invlpg [{}]", in(reg) addr.as_u64(), options(nostack, preserves_flags));
                }
            },
            None => {
                unsafe {
                    let cr3 = self.active_page_table.ok_or("No active page table")?;
                    core::arch::asm!(
                        "mov cr3, {}",
                        in(reg) cr3.as_u64(),
                        options(nostack, preserves_flags)
                    );
                }
            },
        }
        
        Ok(())
    }
    
    fn translate_address(&self, virtual_addr: VirtAddr) -> Result<PhysAddr, &'static str> {
        let va_val = virtual_addr.as_u64();
        let l4_idx = (va_val >> 39) & 0x1FF;
        let l3_idx = (va_val >> 30) & 0x1FF;
        let l2_idx = (va_val >> 21) & 0x1FF;
        let l1_idx = (va_val >> 12) & 0x1FF;
        let offset = va_val & 0xFFF;
        
        let cr3 = self.active_page_table.ok_or("No active page table")?;
        let l4_table = unsafe { &*((layout::DIRECTMAP_BASE + cr3.as_u64()) as *const [u64; 512]) };
        
        if l4_table[l4_idx as usize] & 1 == 0 {
            return Err("L4 entry not present");
        }
        
        let l3_pa = PhysAddr::new(l4_table[l4_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l3_table = unsafe { &*((layout::DIRECTMAP_BASE + l3_pa.as_u64()) as *const [u64; 512]) };
        
        if l3_table[l3_idx as usize] & 1 == 0 {
            return Err("L3 entry not present");
        }
        
        let l2_pa = PhysAddr::new(l3_table[l3_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l2_table = unsafe { &*((layout::DIRECTMAP_BASE + l2_pa.as_u64()) as *const [u64; 512]) };
        
        if l2_table[l2_idx as usize] & 1 == 0 {
            return Err("L2 entry not present");
        }
        
        let l1_pa = PhysAddr::new(l2_table[l2_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l1_table = unsafe { &*((layout::DIRECTMAP_BASE + l1_pa.as_u64()) as *const [u64; 512]) };
        
        if l1_table[l1_idx as usize] & 1 == 0 {
            return Err("Page not present");
        }
        
        let page_pa = PhysAddr::new(l1_table[l1_idx as usize] & 0x000F_FFFF_FFFF_F000);
        Ok(PhysAddr::new(page_pa.as_u64() + offset))
    }
    
    fn get_mapping_info(&self, virtual_addr: VirtAddr) -> Option<&PageMapping> {
        let page_addr = virtual_addr.as_u64() & layout::PAGE_MASK;
        self.mappings.get(&page_addr)
    }
    
    fn update_page_flags(&self, va: VirtAddr, flags: u64) -> Result<(), &'static str> {
        let va_val = va.as_u64();
        let l4_idx = (va_val >> 39) & 0x1FF;
        let l3_idx = (va_val >> 30) & 0x1FF;
        let l2_idx = (va_val >> 21) & 0x1FF;
        let l1_idx = (va_val >> 12) & 0x1FF;
        
        let cr3 = self.active_page_table.ok_or("No active page table")?;
        let l4_table = unsafe { &*((layout::DIRECTMAP_BASE + cr3.as_u64()) as *const [u64; 512]) };
        
        if l4_table[l4_idx as usize] & 1 == 0 {
            return Err("L4 entry not present");
        }
        
        let l3_pa = PhysAddr::new(l4_table[l4_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l3_table = unsafe { &*((layout::DIRECTMAP_BASE + l3_pa.as_u64()) as *const [u64; 512]) };
        
        if l3_table[l3_idx as usize] & 1 == 0 {
            return Err("L3 entry not present");
        }
        
        let l2_pa = PhysAddr::new(l3_table[l3_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l2_table = unsafe { &*((layout::DIRECTMAP_BASE + l2_pa.as_u64()) as *const [u64; 512]) };
        
        if l2_table[l2_idx as usize] & 1 == 0 {
            return Err("L2 entry not present");
        }
        
        let l1_pa = PhysAddr::new(l2_table[l2_idx as usize] & 0x000F_FFFF_FFFF_F000);
        let l1_table = unsafe { &mut *((layout::DIRECTMAP_BASE + l1_pa.as_u64()) as *mut [u64; 512]) };
        
        if l1_table[l1_idx as usize] & 1 == 0 {
            return Err("Page not present");
        }
        
        // Preserve the physical address, update the flags
        let old_pa = l1_table[l1_idx as usize] & 0x000F_FFFF_FFFF_F000;
        l1_table[l1_idx as usize] = old_pa | flags;
        
        Ok(())
    }
}

#[derive(Debug)]
pub struct PagingStats {
    pub total_mappings: usize,
    pub address_spaces: usize,
    pub page_faults: u64,
    pub tlb_flushes: u64,
    pub cow_faults: u64,
    pub demand_loads: u64,
    pub huge_pages: usize,
    pub user_pages: usize,
    pub kernel_pages: usize,
}

pub fn init() -> Result<(), &'static str> {
    let mut manager = PAGING_MANAGER.lock();
    manager.init()
}

pub fn map_page(virtual_addr: VirtAddr, physical_addr: PhysAddr, 
               permissions: PagePermissions) -> Result<(), &'static str> {
    let mut manager = PAGING_MANAGER.lock();
    manager.map_page(virtual_addr, physical_addr, permissions, PageSize::Size4KiB)
}

pub fn map_huge_page(virtual_addr: VirtAddr, physical_addr: PhysAddr, 
                    permissions: PagePermissions, size: PageSize) -> Result<(), &'static str> {
    let mut manager = PAGING_MANAGER.lock();
    manager.map_page(virtual_addr, physical_addr, permissions, size)
}

pub fn unmap_page(virtual_addr: VirtAddr) -> Result<PhysAddr, &'static str> {
    let mut manager = PAGING_MANAGER.lock();
    manager.unmap_page(virtual_addr)
}

pub fn create_address_space(process_id: u32) -> Result<u32, &'static str> {
    let mut manager = PAGING_MANAGER.lock();
    manager.create_address_space(process_id)
}

pub fn switch_address_space(asid: u32) -> Result<(), &'static str> {
    let mut manager = PAGING_MANAGER.lock();
    manager.switch_address_space(asid)
}

pub fn handle_page_fault(virtual_addr: VirtAddr, error_code: u64) -> Result<(), &'static str> {
    let mut manager = PAGING_MANAGER.lock();
    manager.handle_page_fault(virtual_addr, error_code)
}

pub fn flush_tlb(virtual_addr: Option<VirtAddr>) -> Result<(), &'static str> {
    let manager = PAGING_MANAGER.lock();
    manager.flush_tlb(virtual_addr)
}

pub fn get_mapping_info(virtual_addr: VirtAddr) -> Option<PageMapping> {
    let manager = PAGING_MANAGER.lock();
    manager.get_mapping_info(virtual_addr).cloned()
}

pub fn get_paging_stats() -> PagingStats {
    let manager = PAGING_MANAGER.lock();
    PagingStats {
        total_mappings: manager.mappings.len(),
        address_spaces: manager.address_spaces.len(),
        page_faults: PAGING_STATS.page_faults.load(Ordering::Relaxed),
        tlb_flushes: PAGING_STATS.tlb_flushes.load(Ordering::Relaxed),
        cow_faults: PAGING_STATS.cow_faults.load(Ordering::Relaxed),
        demand_loads: PAGING_STATS.demand_loads.load(Ordering::Relaxed),
        huge_pages: PAGING_STATS.huge_pages.load(Ordering::Relaxed),
        user_pages: PAGING_STATS.user_pages.load(Ordering::Relaxed),
        kernel_pages: PAGING_STATS.kernel_pages.load(Ordering::Relaxed),
    }
}

pub fn map_kernel_page(virtual_addr: VirtAddr, physical_addr: PhysAddr) -> Result<(), &'static str> {
    let permissions = PagePermissions::READ | PagePermissions::WRITE | PagePermissions::GLOBAL;
    map_page(virtual_addr, physical_addr, permissions)
}

pub fn map_user_page(virtual_addr: VirtAddr, physical_addr: PhysAddr, 
                    writable: bool) -> Result<(), &'static str> {
    let mut permissions = PagePermissions::READ | PagePermissions::USER;
    if writable {
        permissions = permissions | PagePermissions::WRITE;
    }
    map_page(virtual_addr, physical_addr, permissions)
}

pub fn map_device_memory(virtual_addr: VirtAddr, physical_addr: PhysAddr, 
                        size: usize) -> Result<(), &'static str> {
    let permissions = PagePermissions::READ | PagePermissions::WRITE | 
                     PagePermissions::NO_CACHE | PagePermissions::DEVICE;
    
    let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    for i in 0..page_count {
        let va = VirtAddr::new(virtual_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
        let pa = PhysAddr::new(physical_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
        map_page(va, pa, permissions)?;
    }
    
    Ok(())
}

pub fn translate_address(virtual_addr: VirtAddr) -> Option<PhysAddr> {
    let manager = PAGING_MANAGER.lock();
    manager.translate_address(virtual_addr).ok()
}

pub fn is_mapped(virtual_addr: VirtAddr) -> bool {
    translate_address(virtual_addr).is_some()
}

pub fn get_page_permissions(virtual_addr: VirtAddr) -> Option<PagePermissions> {
    get_mapping_info(virtual_addr).map(|mapping| mapping.permissions)
}

pub fn cleanup_address_space(asid: u32) -> Result<(), &'static str> {
    let mut manager = PAGING_MANAGER.lock();
    
    if let Some(address_space) = manager.address_spaces.remove(&asid) {
        for mapping_addr in &address_space.mappings {
            let _ = manager.unmap_page(*mapping_addr);
        }
        
        frame_alloc::deallocate_frame(address_space.cr3_value);
    }
    
    Ok(())
}

pub fn get_memory_usage() -> (usize, usize) {
    let stats = get_paging_stats();
    (stats.user_pages * layout::PAGE_SIZE, stats.kernel_pages * layout::PAGE_SIZE)
}

pub fn enable_write_protection() {
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr0",
            "or {tmp:e}, 0x10000",
            "mov cr0, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }
}

pub fn disable_write_protection() {
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr0",
            "and {tmp:e}, 0xFFFEFFFF",
            "mov cr0, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }
}

pub fn get_current_cr3() -> PhysAddr {
    let (cr3_frame, _) = Cr3::read();
    cr3_frame.start_address()
}

pub fn set_cr3(page_table_pa: PhysAddr) {
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) page_table_pa.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}

pub fn invalidate_page(virtual_addr: VirtAddr) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) virtual_addr.as_u64(), options(nostack, preserves_flags));
    }
}

pub fn invalidate_all_pages() {
    let cr3 = get_current_cr3();
    set_cr3(cr3);
}

pub fn protect_pages(start_addr: VirtAddr, page_count: usize, permissions: PagePermissions) -> Result<(), &'static str> {
    let mut manager = PAGING_MANAGER.lock();
    
    for i in 0..page_count {
        let va = VirtAddr::new(start_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
        let page_addr = va.as_u64() & layout::PAGE_MASK;
        
        if let Some(mapping) = manager.mappings.get_mut(&page_addr) {
            mapping.permissions = permissions;
            
            // Update the actual page table entry
            let mut pte_flags = 1u64; // Present
            
            if permissions.contains(PagePermissions::WRITE) {
                pte_flags |= 2;
            }
            if permissions.contains(PagePermissions::USER) {
                pte_flags |= 4;
            }
            if permissions.contains(PagePermissions::WRITE_THROUGH) {
                pte_flags |= 8;
            }
            if permissions.contains(PagePermissions::NO_CACHE) {
                pte_flags |= 16;
            }
            if permissions.contains(PagePermissions::GLOBAL) {
                pte_flags |= 256;
            }
            if !permissions.contains(PagePermissions::EXECUTE) {
                pte_flags |= 1u64 << 63;
            }
            
            // Update the page table entry flags
            manager.update_page_flags(va, pte_flags)?;
            manager.flush_tlb(Some(va));
        } else {
            return Err("Page not mapped");
        }
    }
    
    Ok(())
}

fn get_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}