#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::ptr;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::nonos_layout as layout;
use crate::memory::nonos_frame_alloc as frame_alloc;

static VMAP_ALLOCATOR: Mutex<VmapAllocator> = Mutex::new(VmapAllocator::new());
static ALLOCATION_STATS: AllocationStats = AllocationStats::new();

const MAX_ORDER: usize = 20;
const MIN_ORDER: usize = 12;

struct VmapAllocator {
    free_lists: [Vec<BuddyBlock>; MAX_ORDER - MIN_ORDER + 1],
    allocated_blocks: BTreeMap<u64, AllocatedBlock>,
    base_addr: u64,
    total_size: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy)]
struct BuddyBlock {
    addr: u64,
    order: usize,
}

#[derive(Debug, Clone, Copy)]
struct AllocatedBlock {
    addr: u64,
    size: usize,
    order: usize,
    flags: u32,
}


struct AllocationStats {
    total_allocated: AtomicU64,
    peak_allocated: AtomicU64,
    allocation_count: AtomicUsize,
    free_count: AtomicUsize,
}

impl AllocationStats {
    const fn new() -> Self {
        Self {
            total_allocated: AtomicU64::new(0),
            peak_allocated: AtomicU64::new(0),
            allocation_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
        }
    }

    fn record_allocation(&self, size: u64) {
        let new_total = self.total_allocated.fetch_add(size, Ordering::Relaxed) + size;
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        
        loop {
            let current_peak = self.peak_allocated.load(Ordering::Relaxed);
            if new_total <= current_peak {
                break;
            }
            if self.peak_allocated.compare_exchange_weak(
                current_peak, 
                new_total, 
                Ordering::Relaxed, 
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
    }

    fn record_deallocation(&self, size: u64) {
        self.total_allocated.fetch_sub(size, Ordering::Relaxed);
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }
}

impl VmapAllocator {
    const fn new() -> Self {
        const INIT: Vec<BuddyBlock> = Vec::new();
        Self {
            free_lists: [INIT; MAX_ORDER - MIN_ORDER + 1],
            allocated_blocks: BTreeMap::new(),
            base_addr: layout::VMAP_BASE,
            total_size: layout::VMAP_SIZE,
            initialized: false,
        }
    }

    fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }

        for list in &mut self.free_lists {
            list.clear();
        }
        self.allocated_blocks.clear();

        let initial_order = self.size_to_order(self.total_size as usize);
        if initial_order <= MAX_ORDER {
            self.free_lists[initial_order - MIN_ORDER].push(BuddyBlock {
                addr: self.base_addr,
                order: initial_order,
            });
        }

        self.initialized = true;
        Ok(())
    }

    fn size_to_order(&self, size: usize) -> usize {
        let size = size.max(1 << MIN_ORDER);
        let mut order = MIN_ORDER;
        while (1 << order) < size && order < MAX_ORDER {
            order += 1;
        }
        order
    }

    fn order_to_size(&self, order: usize) -> usize {
        1 << order
    }

    fn get_buddy_addr(&self, addr: u64, order: usize) -> u64 {
        addr ^ (1u64 << order)
    }

    fn find_block(&mut self, order: usize) -> Option<BuddyBlock> {
        for current_order in order..=MAX_ORDER {
            let list_idx = current_order.saturating_sub(MIN_ORDER);
            if list_idx < self.free_lists.len() && !self.free_lists[list_idx].is_empty() {
                let mut block = self.free_lists[list_idx].remove(0);
                
                while block.order > order {
                    let split_order = block.order - 1;
                    let split_size = 1u64 << split_order;
                    let buddy_addr = block.addr + split_size;
                    
                    let buddy_idx = split_order.saturating_sub(MIN_ORDER);
                    if buddy_idx < self.free_lists.len() {
                        self.free_lists[buddy_idx].push(BuddyBlock {
                            addr: buddy_addr,
                            order: split_order,
                        });
                    }
                    
                    block.order = split_order;
                    
                    if block.order == order {
                        break;
                    }
                }
                
                return Some(block);
            }
        }
        None
    }

    fn merge_buddies(&mut self, mut block: BuddyBlock) {
        while block.order < MAX_ORDER {
            let buddy_addr = self.get_buddy_addr(block.addr, block.order);
            let list_idx = block.order.saturating_sub(MIN_ORDER);
            
            if list_idx >= self.free_lists.len() {
                break;
            }
            
            let buddy_pos = self.free_lists[list_idx].iter().position(|b| b.addr == buddy_addr);
            
            if let Some(pos) = buddy_pos {
                self.free_lists[list_idx].remove(pos);
                
                block = BuddyBlock {
                    addr: block.addr.min(buddy_addr),
                    order: block.order + 1,
                };
            } else {
                break;
            }
        }
        
        let list_idx = block.order.saturating_sub(MIN_ORDER);
        if list_idx < self.free_lists.len() {
            self.free_lists[list_idx].push(block);
        }
    }

    fn allocate_range(&mut self, size: usize, align: usize) -> Result<VirtAddr, &'static str> {
        if !self.initialized {
            return Err("Allocator not initialized");
        }

        if size == 0 {
            return Err("Invalid allocation size");
        }

        if !align.is_power_of_two() {
            return Err("Alignment must be power of two");
        }

        let aligned_size = self.align_up(size, align.max(layout::PAGE_SIZE));
        let required_order = self.size_to_order(aligned_size);

        if required_order > MAX_ORDER {
            return Err("Allocation too large");
        }

        if let Some(block) = self.find_block(required_order) {
            if block.addr < self.base_addr || 
               block.addr + (1u64 << block.order) > self.base_addr + self.total_size {
                return Err("Block outside valid range");
            }

            let allocated_block = AllocatedBlock {
                addr: block.addr,
                size: aligned_size,
                order: block.order,
                flags: 0,
            };

            self.allocated_blocks.insert(block.addr, allocated_block);
            ALLOCATION_STATS.record_allocation(aligned_size as u64);

            Ok(VirtAddr::new(block.addr))
        } else {
            Err("Out of virtual memory")
        }
    }

    fn deallocate_range(&mut self, addr: VirtAddr) -> Result<(), &'static str> {
        let addr_u64 = addr.as_u64();
        
        if let Some(allocated_block) = self.allocated_blocks.remove(&addr_u64) {
            let block = BuddyBlock {
                addr: allocated_block.addr,
                order: allocated_block.order,
            };
            
            self.merge_buddies(block);
            ALLOCATION_STATS.record_deallocation(allocated_block.size as u64);
            
            Ok(())
        } else {
            Err("Invalid deallocation address")
        }
    }

    const fn align_up(&self, value: usize, align: usize) -> usize {
        (value + align - 1) & !(align - 1)
    }
}

pub fn init() -> Result<(), &'static str> {
    let mut allocator = VMAP_ALLOCATOR.lock();
    allocator.init()
}

pub fn allocate_pages(count: usize) -> Result<VirtAddr, &'static str> {
    if count == 0 {
        return Err("Invalid page count");
    }

    let size = count * layout::PAGE_SIZE;
    let mut allocator = VMAP_ALLOCATOR.lock();
    let virt_addr = allocator.allocate_range(size, layout::PAGE_SIZE)?;

    for i in 0..count {
        let page_addr = VirtAddr::new(virt_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
        let phys_addr = frame_alloc::allocate_frame()
            .ok_or("Failed to allocate physical frame")?;
        
        map_page(page_addr, phys_addr)?;
    }

    unsafe {
        ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, size);
    }

    Ok(virt_addr)
}

pub fn deallocate_pages(addr: VirtAddr, count: usize) -> Result<(), &'static str> {
    if count == 0 {
        return Err("Invalid page count");
    }

    for i in 0..count {
        let page_addr = VirtAddr::new(addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
        unmap_page(page_addr)?;
    }

    let mut allocator = VMAP_ALLOCATOR.lock();
    allocator.deallocate_range(addr)
}

pub fn allocate_aligned(size: usize, align: usize) -> Result<VirtAddr, &'static str> {
    if size == 0 || align == 0 || !align.is_power_of_two() {
        return Err("Invalid allocation parameters");
    }

    let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    let total_size = page_count * layout::PAGE_SIZE;
    
    let mut allocator = VMAP_ALLOCATOR.lock();
    let virt_addr = allocator.allocate_range(total_size, align)?;

    for i in 0..page_count {
        let page_addr = VirtAddr::new(virt_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
        let phys_addr = frame_alloc::allocate_frame()
            .ok_or("Failed to allocate physical frame")?;
        
        map_page(page_addr, phys_addr)?;
    }

    unsafe {
        ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, total_size);
    }

    Ok(virt_addr)
}

pub fn deallocate_aligned(addr: VirtAddr, size: usize) -> Result<(), &'static str> {
    let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    
    for i in 0..page_count {
        let page_addr = VirtAddr::new(addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
        unmap_page(page_addr)?;
    }

    let mut allocator = VMAP_ALLOCATOR.lock();
    allocator.deallocate_range(addr)
}

pub fn free_pages(addr: VirtAddr, count: usize) -> Result<(), &'static str> {
    if count == 0 {
        return Err("Invalid page count");
    }

    let size = count * layout::PAGE_SIZE;

    for i in 0..count {
        let page_addr = VirtAddr::new(addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
        
        if let Some(phys_addr) = unmap_page(page_addr)? {
            frame_alloc::deallocate_frame(phys_addr);
        }
    }

    let mut allocator = VMAP_ALLOCATOR.lock();
    allocator.deallocate_range(addr)?;

    Ok(())
}

pub fn free_aligned(addr: VirtAddr, size: usize) -> Result<(), &'static str> {
    let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    free_pages(addr, page_count)
}

fn map_page(virt_addr: VirtAddr, phys_addr: PhysAddr) -> Result<(), &'static str> {
    use crate::memory::nonos_virt;
    
    unsafe {
        nonos_virt::map_page_4k(virt_addr, phys_addr, true, true, false)
            .map_err(|_| "Failed to map page")?;
    }
    
    Ok(())
}

fn unmap_page(virt_addr: VirtAddr) -> Result<Option<PhysAddr>, &'static str> {
    use crate::memory::nonos_virt;
    
    unsafe {
        let phys_addr = nonos_virt::translate_addr(virt_addr).map_err(|_| "Address translation failed")?;
        nonos_virt::unmap_page(virt_addr)
            .map_err(|_| "Failed to unmap page")?;
        Ok(Some(phys_addr))
    }
}

pub fn get_allocation_stats() -> AllocStats {
    AllocStats {
        total_allocated: ALLOCATION_STATS.total_allocated.load(Ordering::Relaxed),
        peak_allocated: ALLOCATION_STATS.peak_allocated.load(Ordering::Relaxed),
        allocation_count: ALLOCATION_STATS.allocation_count.load(Ordering::Relaxed),
        free_count: ALLOCATION_STATS.free_count.load(Ordering::Relaxed),
        active_ranges: VMAP_ALLOCATOR.lock().allocated_blocks.len(),
    }
}

#[derive(Debug)]
pub struct AllocStats {
    pub total_allocated: u64,
    pub peak_allocated: u64,
    pub allocation_count: usize,
    pub free_count: usize,
    pub active_ranges: usize,
}

pub fn is_valid_allocation(addr: VirtAddr) -> bool {
    let allocator = VMAP_ALLOCATOR.lock();
    allocator.allocated_blocks.contains_key(&addr.as_u64())
}

pub fn get_allocation_size(addr: VirtAddr) -> Option<usize> {
    let allocator = VMAP_ALLOCATOR.lock();
    allocator.allocated_blocks.get(&addr.as_u64()).map(|block| block.size)
}

pub fn validate_range(addr: VirtAddr, size: usize) -> bool {
    if addr.as_u64() < layout::VMAP_BASE || 
       addr.as_u64() + size as u64 > layout::VMAP_BASE + layout::VMAP_SIZE {
        return false;
    }

    let allocator = VMAP_ALLOCATOR.lock();
    if let Some(block) = allocator.allocated_blocks.get(&addr.as_u64()) {
        let start = block.addr;
        let end = start + block.size as u64;
        addr.as_u64() >= start && addr.as_u64() + size as u64 <= end
    } else {
        false
    }
}

pub fn total_allocated() -> u64 {
    ALLOCATION_STATS.total_allocated.load(Ordering::Relaxed)
}

pub fn peak_allocated() -> u64 {
    ALLOCATION_STATS.peak_allocated.load(Ordering::Relaxed)
}