#![no_std]

use core::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::nonos_layout as layout;
use crate::memory::nonos_frame_alloc as frame_alloc;

static PAGE_ALLOCATOR: Mutex<PageAllocator> = Mutex::new(PageAllocator::new());
static ALLOCATOR_STATS: AllocatorStats = AllocatorStats::new();

struct PageAllocator {
    allocated_pages: Vec<AllocatedPage>,
    next_page_id: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy)]
struct AllocatedPage {
    page_id: u64,
    virtual_addr: VirtAddr,
    physical_addr: PhysAddr,
    allocation_time: u64,
    size: usize,
}

struct AllocatorStats {
    total_allocations: AtomicU64,
    total_deallocations: AtomicU64,
    active_pages: AtomicUsize,
    bytes_allocated: AtomicU64,
    peak_pages: AtomicUsize,
}

impl AllocatorStats {
    const fn new() -> Self {
        Self {
            total_allocations: AtomicU64::new(0),
            total_deallocations: AtomicU64::new(0),
            active_pages: AtomicUsize::new(0),
            bytes_allocated: AtomicU64::new(0),
            peak_pages: AtomicUsize::new(0),
        }
    }

    fn record_allocation(&self, size: usize) {
        self.total_allocations.fetch_add(1, Ordering::Relaxed);
        let new_count = self.active_pages.fetch_add(1, Ordering::Relaxed) + 1;
        self.bytes_allocated.fetch_add(size as u64, Ordering::Relaxed);

        loop {
            let current_peak = self.peak_pages.load(Ordering::Relaxed);
            if new_count <= current_peak {
                break;
            }
            if self.peak_pages.compare_exchange_weak(
                current_peak,
                new_count,
                Ordering::Relaxed,
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
    }

    fn record_deallocation(&self, size: usize) {
        self.total_deallocations.fetch_add(1, Ordering::Relaxed);
        self.active_pages.fetch_sub(1, Ordering::Relaxed);
        self.bytes_allocated.fetch_sub(size as u64, Ordering::Relaxed);
    }
}

impl PageAllocator {
    const fn new() -> Self {
        Self {
            allocated_pages: Vec::new(),
            next_page_id: 1,
            initialized: false,
        }
    }

    fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }

        self.allocated_pages.clear();
        self.next_page_id = 1;
        self.initialized = true;

        Ok(())
    }

    fn allocate_page(&mut self, size: usize) -> Result<VirtAddr, &'static str> {
        if !self.initialized {
            return Err("Page allocator not initialized");
        }

        if size == 0 {
            return Err("Invalid allocation size");
        }

        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        let total_size = page_count * layout::PAGE_SIZE;

        let va = self.allocate_virtual_pages(page_count)?;
        let pa = self.get_physical_address(va)?;

        let page_id = self.next_page_id;
        self.next_page_id += 1;

        let allocated_page = AllocatedPage {
            page_id,
            virtual_addr: va,
            physical_addr: pa,
            allocation_time: self.get_timestamp(),
            size: total_size,
        };

        self.allocated_pages.push(allocated_page);
        ALLOCATOR_STATS.record_allocation(total_size);

        unsafe {
            core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, total_size);
        }

        Ok(va)
    }

    fn deallocate_page(&mut self, va: VirtAddr) -> Result<(), &'static str> {
        let page_idx = self.allocated_pages.iter().position(|p| p.virtual_addr == va)
            .ok_or("Page not found")?;

        let page = self.allocated_pages.remove(page_idx);

        unsafe {
            core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, page.size);
        }

        self.free_virtual_pages(va, page.size / layout::PAGE_SIZE)?;
        ALLOCATOR_STATS.record_deallocation(page.size);

        Ok(())
    }

    fn get_page_info(&self, va: VirtAddr) -> Option<&AllocatedPage> {
        self.allocated_pages.iter().find(|p| p.virtual_addr == va)
    }

    fn allocate_virtual_pages(&self, page_count: usize) -> Result<VirtAddr, &'static str> {
        let mut allocated_frames = Vec::new();

        for _ in 0..page_count {
            let frame = frame_alloc::allocate_frame()
                .ok_or("Failed to allocate physical frame")?;
            allocated_frames.push(frame);
        }

        let first_frame = allocated_frames[0];
        let va = VirtAddr::new(layout::VMAP_BASE + first_frame.as_u64());

        for (i, frame) in allocated_frames.iter().enumerate() {
            let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
            self.map_page(page_va, *frame)?;
        }

        Ok(va)
    }

    fn free_virtual_pages(&self, va: VirtAddr, page_count: usize) -> Result<(), &'static str> {
        for i in 0..page_count {
            let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
            let pa = self.get_physical_address(page_va)?;
            
            self.unmap_page(page_va)?;
            frame_alloc::deallocate_frame(pa);
        }

        Ok(())
    }

    fn map_page(&self, va: VirtAddr, pa: PhysAddr) -> Result<(), &'static str> {
        use crate::memory::nonos_virt;

        nonos_virt::map_page_4k(va, pa, true, false, false)
            .map_err(|_| "Failed to map page")
    }

    fn unmap_page(&self, va: VirtAddr) -> Result<(), &'static str> {
        use crate::memory::nonos_virt;

        nonos_virt::unmap_page(va)
            .map_err(|_| "Failed to unmap page")
    }

    fn get_physical_address(&self, va: VirtAddr) -> Result<PhysAddr, &'static str> {
        use crate::memory::nonos_virt;

        nonos_virt::translate_addr(va)
            .map_err(|_| "Address translation failed")
    }

    fn get_timestamp(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    fn get_allocator_stats(&self) -> PageAllocatorStats {
        PageAllocatorStats {
            total_allocations: ALLOCATOR_STATS.total_allocations.load(Ordering::Relaxed),
            total_deallocations: ALLOCATOR_STATS.total_deallocations.load(Ordering::Relaxed),
            active_pages: ALLOCATOR_STATS.active_pages.load(Ordering::Relaxed),
            bytes_allocated: ALLOCATOR_STATS.bytes_allocated.load(Ordering::Relaxed),
            peak_pages: ALLOCATOR_STATS.peak_pages.load(Ordering::Relaxed),
            allocated_pages: self.allocated_pages.len(),
        }
    }
}

#[derive(Debug)]
pub struct PageAllocatorStats {
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub active_pages: usize,
    pub bytes_allocated: u64,
    pub peak_pages: usize,
    pub allocated_pages: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct PageInfo {
    pub page_id: u64,
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub allocation_time: u64,
    pub size: usize,
}

pub fn init() -> Result<(), &'static str> {
    let mut allocator = PAGE_ALLOCATOR.lock();
    allocator.init()
}

pub fn allocate_page() -> Result<VirtAddr, &'static str> {
    let mut allocator = PAGE_ALLOCATOR.lock();
    allocator.allocate_page(layout::PAGE_SIZE)
}

pub fn allocate_pages(count: usize) -> Result<VirtAddr, &'static str> {
    let mut allocator = PAGE_ALLOCATOR.lock();
    allocator.allocate_page(count * layout::PAGE_SIZE)
}

pub fn allocate_sized(size: usize) -> Result<VirtAddr, &'static str> {
    let mut allocator = PAGE_ALLOCATOR.lock();
    allocator.allocate_page(size)
}

pub fn deallocate_page(va: VirtAddr) -> Result<(), &'static str> {
    let mut allocator = PAGE_ALLOCATOR.lock();
    allocator.deallocate_page(va)
}

pub fn get_page_info(va: VirtAddr) -> Option<PageInfo> {
    let allocator = PAGE_ALLOCATOR.lock();
    allocator.get_page_info(va).map(|p| PageInfo {
        page_id: p.page_id,
        virtual_addr: p.virtual_addr,
        physical_addr: p.physical_addr,
        allocation_time: p.allocation_time,
        size: p.size,
    })
}

pub fn get_stats() -> PageAllocatorStats {
    let allocator = PAGE_ALLOCATOR.lock();
    allocator.get_allocator_stats()
}

pub fn is_allocated(va: VirtAddr) -> bool {
    let allocator = PAGE_ALLOCATOR.lock();
    allocator.get_page_info(va).is_some()
}

pub fn get_allocation_count() -> usize {
    ALLOCATOR_STATS.active_pages.load(Ordering::Relaxed)
}

pub fn get_total_bytes_allocated() -> u64 {
    ALLOCATOR_STATS.bytes_allocated.load(Ordering::Relaxed)
}

pub fn get_peak_pages() -> usize {
    ALLOCATOR_STATS.peak_pages.load(Ordering::Relaxed)
}