#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::collections::BTreeMap;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::nonos_layout as layout;

static PAGE_INFO_MANAGER: Mutex<PageInfoManager> = Mutex::new(PageInfoManager::new());
static PAGE_STATS: PageStats = PageStats::new();

#[derive(Debug, Clone, Copy)]
pub struct PageInfo {
    pub physical_addr: PhysAddr,
    pub virtual_addr: Option<VirtAddr>,
    pub flags: PageFlags,
    pub ref_count: u32,
    pub allocation_time: u64,
    pub last_access: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFlags {
    bits: u32,
}

impl PageFlags {
    pub const PRESENT: Self = Self { bits: 1 << 0 };
    pub const WRITABLE: Self = Self { bits: 1 << 1 };
    pub const USER: Self = Self { bits: 1 << 2 };
    pub const DIRTY: Self = Self { bits: 1 << 3 };
    pub const ACCESSED: Self = Self { bits: 1 << 4 };
    pub const LOCKED: Self = Self { bits: 1 << 5 };
    pub const ENCRYPTED: Self = Self { bits: 1 << 6 };

    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub const fn union(self, other: Self) -> Self {
        Self { bits: self.bits | other.bits }
    }
}

struct PageInfoManager {
    pages: BTreeMap<u64, PageInfo>,
    initialized: bool,
}

struct PageStats {
    total_pages: AtomicUsize,
    mapped_pages: AtomicUsize,
    dirty_pages: AtomicUsize,
    locked_pages: AtomicUsize,
    page_accesses: AtomicU64,
}

impl PageStats {
    const fn new() -> Self {
        Self {
            total_pages: AtomicUsize::new(0),
            mapped_pages: AtomicUsize::new(0),
            dirty_pages: AtomicUsize::new(0),
            locked_pages: AtomicUsize::new(0),
            page_accesses: AtomicU64::new(0),
        }
    }
}

impl PageInfoManager {
    const fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            initialized: false,
        }
    }

    fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }
        self.pages.clear();
        self.initialized = true;
        Ok(())
    }

    fn add_page(&mut self, pa: PhysAddr, va: Option<VirtAddr>, flags: PageFlags) -> Result<(), &'static str> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        let info = PageInfo {
            physical_addr: pa,
            virtual_addr: va,
            flags,
            ref_count: 1,
            allocation_time: get_timestamp(),
            last_access: get_timestamp(),
        };

        self.pages.insert(page_num, info);
        PAGE_STATS.total_pages.fetch_add(1, Ordering::Relaxed);
        
        if va.is_some() {
            PAGE_STATS.mapped_pages.fetch_add(1, Ordering::Relaxed);
        }
        if flags.contains(PageFlags::DIRTY) {
            PAGE_STATS.dirty_pages.fetch_add(1, Ordering::Relaxed);
        }
        if flags.contains(PageFlags::LOCKED) {
            PAGE_STATS.locked_pages.fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }

    fn remove_page(&mut self, pa: PhysAddr) -> Result<(), &'static str> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        
        if let Some(info) = self.pages.remove(&page_num) {
            PAGE_STATS.total_pages.fetch_sub(1, Ordering::Relaxed);
            
            if info.virtual_addr.is_some() {
                PAGE_STATS.mapped_pages.fetch_sub(1, Ordering::Relaxed);
            }
            if info.flags.contains(PageFlags::DIRTY) {
                PAGE_STATS.dirty_pages.fetch_sub(1, Ordering::Relaxed);
            }
            if info.flags.contains(PageFlags::LOCKED) {
                PAGE_STATS.locked_pages.fetch_sub(1, Ordering::Relaxed);
            }
            
            Ok(())
        } else {
            Err("Page not found")
        }
    }

    fn get_page_info(&self, pa: PhysAddr) -> Option<PageInfo> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        self.pages.get(&page_num).copied()
    }

    fn update_flags(&mut self, pa: PhysAddr, flags: PageFlags) -> Result<(), &'static str> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        
        if let Some(info) = self.pages.get_mut(&page_num) {
            let old_flags = info.flags;
            info.flags = flags;
            info.last_access = get_timestamp();

            if old_flags.contains(PageFlags::DIRTY) != flags.contains(PageFlags::DIRTY) {
                if flags.contains(PageFlags::DIRTY) {
                    PAGE_STATS.dirty_pages.fetch_add(1, Ordering::Relaxed);
                } else {
                    PAGE_STATS.dirty_pages.fetch_sub(1, Ordering::Relaxed);
                }
            }

            PAGE_STATS.page_accesses.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err("Page not found")
        }
    }
}

fn get_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

pub fn init() -> Result<(), &'static str> {
    let mut manager = PAGE_INFO_MANAGER.lock();
    manager.init()
}

pub fn add_page(pa: PhysAddr, va: Option<VirtAddr>, flags: PageFlags) -> Result<(), &'static str> {
    let mut manager = PAGE_INFO_MANAGER.lock();
    manager.add_page(pa, va, flags)
}

pub fn remove_page(pa: PhysAddr) -> Result<(), &'static str> {
    let mut manager = PAGE_INFO_MANAGER.lock();
    manager.remove_page(pa)
}

pub fn get_page_info(pa: PhysAddr) -> Option<PageInfo> {
    let manager = PAGE_INFO_MANAGER.lock();
    manager.get_page_info(pa)
}

pub fn update_page_flags(pa: PhysAddr, flags: PageFlags) -> Result<(), &'static str> {
    let mut manager = PAGE_INFO_MANAGER.lock();
    manager.update_flags(pa, flags)
}

pub fn get_page_stats() -> (usize, usize, usize, usize, u64) {
    (
        PAGE_STATS.total_pages.load(Ordering::Relaxed),
        PAGE_STATS.mapped_pages.load(Ordering::Relaxed),
        PAGE_STATS.dirty_pages.load(Ordering::Relaxed),
        PAGE_STATS.locked_pages.load(Ordering::Relaxed),
        PAGE_STATS.page_accesses.load(Ordering::Relaxed),
    )
}