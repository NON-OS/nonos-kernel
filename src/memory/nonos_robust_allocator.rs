//! Robust Page Frame Allocator
//!
//! Production-grade page frame allocation with buddy system and defragmentation

use alloc::{vec::Vec, collections::BTreeMap};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::{PhysAddr, structures::paging::PageSize, structures::paging::Size4KiB};

/// Page frame allocator using buddy system algorithm
pub struct BuddyAllocator {
    /// Free lists for each order (0 = 4KB, 1 = 8KB, 2 = 16KB, etc.)
    free_lists: [Mutex<Vec<PhysAddr>>; MAX_ORDER],
    
    /// Bitmap to track allocated pages
    allocation_bitmap: Mutex<Vec<u64>>,
    
    /// Memory region information
    memory_start: PhysAddr,
    memory_size: usize,
    total_pages: usize,
    
    /// Statistics
    allocated_pages: AtomicUsize,
    free_pages: AtomicUsize,
    allocation_count: AtomicU64,
    deallocation_count: AtomicU64,
    fragmentation_events: AtomicU64,
    
    /// Defragmentation state
    defrag_threshold: usize,
    last_defrag_time: AtomicU64,
}

/// Maximum buddy order (supports up to 4MB allocations)
const MAX_ORDER: usize = 10;

/// Page size in bytes
const PAGE_SIZE: usize = 4096;

/// Allocation statistics
#[derive(Debug, Clone)]
pub struct AllocationStats {
    pub total_pages: usize,
    pub allocated_pages: usize,
    pub free_pages: usize,
    pub allocation_count: u64,
    pub deallocation_count: u64,
    pub fragmentation_events: u64,
    pub largest_free_block: usize,
    pub fragmentation_ratio: f64,
}

/// Memory region descriptor
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub size: usize,
    pub region_type: MemoryRegionType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryRegionType {
    Available,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    Unusable,
    Disabled,
}

impl BuddyAllocator {
    /// Create new buddy allocator
    pub fn new(memory_start: PhysAddr, memory_size: usize) -> Result<Self, &'static str> {
        let total_pages = memory_size / PAGE_SIZE;
        let bitmap_size = (total_pages + 63) / 64; // Round up for u64 chunks
        
        // Validate memory alignment
        if memory_start.as_u64() % PAGE_SIZE as u64 != 0 {
            return Err("Memory start must be page-aligned");
        }
        
        if memory_size % PAGE_SIZE != 0 {
            return Err("Memory size must be page-aligned");
        }
        
        // Initialize free lists
        let free_lists: [Mutex<Vec<PhysAddr>>; MAX_ORDER] = [
            Mutex::new(Vec::new()), Mutex::new(Vec::new()), Mutex::new(Vec::new()),
            Mutex::new(Vec::new()), Mutex::new(Vec::new()), Mutex::new(Vec::new()),
            Mutex::new(Vec::new()), Mutex::new(Vec::new()), Mutex::new(Vec::new()),
            Mutex::new(Vec::new()),
        ];
        
        let allocator = BuddyAllocator {
            free_lists,
            allocation_bitmap: Mutex::new(vec![0u64; bitmap_size]),
            memory_start,
            memory_size,
            total_pages,
            allocated_pages: AtomicUsize::new(0),
            free_pages: AtomicUsize::new(total_pages),
            allocation_count: AtomicU64::new(0),
            deallocation_count: AtomicU64::new(0),
            fragmentation_events: AtomicU64::new(0),
            defrag_threshold: total_pages / 10, // Defrag when 10% fragmented
            last_defrag_time: AtomicU64::new(0),
        };
        
        Ok(allocator)
    }
    
    /// Initialize allocator with available memory regions
    pub fn initialize(&self, regions: &[MemoryRegion]) -> Result<(), &'static str> {
        // Process memory regions and add free blocks to buddy system
        for region in regions {
            if region.region_type == MemoryRegionType::Available {
                self.add_free_region(region.start, region.size)?;
            }
        }
        
        Ok(())
    }
    
    /// Add free memory region to buddy system
    fn add_free_region(&self, start: PhysAddr, size: usize) -> Result<(), &'static str> {
        let pages = size / PAGE_SIZE;
        let mut current_addr = start;
        let mut remaining_pages = pages;
        
        // Add blocks of maximum possible size first
        while remaining_pages > 0 {
            let order = self.find_max_order_for_pages(remaining_pages);
            let block_pages = 1 << order;
            
            // Align to block boundary
            let block_size = block_pages * PAGE_SIZE;
            let aligned_addr = PhysAddr::new((current_addr.as_u64() + block_size as u64 - 1) & !(block_size as u64 - 1));
            
            if aligned_addr != current_addr {
                // Handle unaligned start - add smaller blocks
                let skip_pages = (aligned_addr.as_u64() - current_addr.as_u64()) as usize / PAGE_SIZE;
                if skip_pages > 0 && skip_pages <= remaining_pages {
                    self.add_free_block_recursive(current_addr, skip_pages);
                    current_addr = aligned_addr;
                    remaining_pages -= skip_pages;
                }
                continue;
            }
            
            // Add aligned block
            self.free_lists[order].lock().push(current_addr);
            current_addr = PhysAddr::new(current_addr.as_u64() + block_size as u64);
            remaining_pages -= block_pages;
        }
        
        Ok(())
    }
    
    /// Recursively add free blocks of appropriate sizes
    fn add_free_block_recursive(&self, addr: PhysAddr, pages: usize) {
        if pages == 0 {
            return;
        }
        
        let order = self.find_max_order_for_pages(pages);
        let block_pages = 1 << order;
        
        self.free_lists[order].lock().push(addr);
        
        if pages > block_pages {
            let next_addr = PhysAddr::new(addr.as_u64() + (block_pages * PAGE_SIZE) as u64);
            self.add_free_block_recursive(next_addr, pages - block_pages);
        }
    }
    
    /// Find maximum order that fits within page count
    fn find_max_order_for_pages(&self, pages: usize) -> usize {
        let mut order = 0;
        while order < MAX_ORDER - 1 && (1 << (order + 1)) <= pages {
            order += 1;
        }
        order
    }
    
    /// Allocate contiguous pages
    pub fn allocate_pages(&self, page_count: usize) -> Option<PhysAddr> {
        if page_count == 0 {
            return None;
        }
        
        let order = self.find_required_order(page_count);
        if order >= MAX_ORDER {
            return None;
        }
        
        let addr = self.allocate_block(order)?;
        
        // Mark pages as allocated in bitmap
        self.mark_pages_allocated(addr, 1 << order);
        
        // Update statistics
        self.allocated_pages.fetch_add(1 << order, Ordering::Relaxed);
        self.free_pages.fetch_sub(1 << order, Ordering::Relaxed);
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        
        // Check if defragmentation is needed
        self.check_defragmentation_need();
        
        Some(addr)
    }
    
    /// Allocate single page
    pub fn allocate_page(&self) -> Option<PhysAddr> {
        self.allocate_pages(1)
    }
    
    /// Deallocate pages
    pub fn deallocate_pages(&self, addr: PhysAddr, page_count: usize) -> Result<(), &'static str> {
        if page_count == 0 {
            return Ok(());
        }
        
        if !self.is_valid_address(addr) {
            return Err("Invalid address for deallocation");
        }
        
        let order = self.find_required_order(page_count);
        if order >= MAX_ORDER {
            return Err("Page count too large");
        }
        
        // Check if pages are actually allocated
        if !self.are_pages_allocated(addr, 1 << order) {
            return Err("Attempting to deallocate unallocated pages");
        }
        
        // Mark pages as free in bitmap
        self.mark_pages_free(addr, 1 << order);
        
        // Add block back to free list and try to coalesce
        self.deallocate_block(addr, order);
        
        // Update statistics
        self.allocated_pages.fetch_sub(1 << order, Ordering::Relaxed);
        self.free_pages.fetch_add(1 << order, Ordering::Relaxed);
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// Deallocate single page
    pub fn deallocate_page(&self, addr: PhysAddr) -> Result<(), &'static str> {
        self.deallocate_pages(addr, 1)
    }
    
    /// Allocate block of specific order
    fn allocate_block(&self, order: usize) -> Option<PhysAddr> {
        // Try to allocate from current order
        if let Some(addr) = self.free_lists[order].lock().pop() {
            return Some(addr);
        }
        
        // Try to split a larger block
        if order < MAX_ORDER - 1 {
            if let Some(larger_addr) = self.allocate_block(order + 1) {
                let buddy_addr = PhysAddr::new(larger_addr.as_u64() + ((1 << order) * PAGE_SIZE) as u64);
                self.free_lists[order].lock().push(buddy_addr);
                return Some(larger_addr);
            }
        }
        
        None
    }
    
    /// Deallocate block and attempt coalescing
    fn deallocate_block(&self, addr: PhysAddr, order: usize) {
        if order >= MAX_ORDER - 1 {
            // Can't coalesce at maximum order
            self.free_lists[order].lock().push(addr);
            return;
        }
        
        // Find buddy address
        let block_size = (1 << order) * PAGE_SIZE;
        let buddy_addr = self.find_buddy_address(addr, order);
        
        // Check if buddy is free
        let mut free_list = self.free_lists[order].lock();
        if let Some(pos) = free_list.iter().position(|&a| a == buddy_addr) {
            // Buddy is free - coalesce
            free_list.swap_remove(pos);
            drop(free_list);
            
            let coalesced_addr = if addr < buddy_addr { addr } else { buddy_addr };
            self.deallocate_block(coalesced_addr, order + 1);
        } else {
            // Buddy not free - add to current order
            free_list.push(addr);
        }
    }
    
    /// Find buddy address for coalescing
    fn find_buddy_address(&self, addr: PhysAddr, order: usize) -> PhysAddr {
        let block_size = (1 << order) * PAGE_SIZE;
        let offset_from_start = addr.as_u64() - self.memory_start.as_u64();
        let buddy_offset = offset_from_start ^ block_size as u64;
        PhysAddr::new(self.memory_start.as_u64() + buddy_offset)
    }
    
    /// Find minimum order needed for page count
    fn find_required_order(&self, page_count: usize) -> usize {
        let mut order = 0;
        while (1 << order) < page_count && order < MAX_ORDER {
            order += 1;
        }
        order
    }
    
    /// Check if address is within managed memory range
    fn is_valid_address(&self, addr: PhysAddr) -> bool {
        let start = self.memory_start.as_u64();
        let end = start + self.memory_size as u64;
        let addr_val = addr.as_u64();
        
        addr_val >= start && addr_val < end && (addr_val - start) % PAGE_SIZE as u64 == 0
    }
    
    /// Mark pages as allocated in bitmap
    fn mark_pages_allocated(&self, addr: PhysAddr, page_count: usize) {
        let page_index = self.addr_to_page_index(addr);
        let mut bitmap = self.allocation_bitmap.lock();
        
        for i in 0..page_count {
            let idx = page_index + i;
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            
            if word_idx < bitmap.len() {
                bitmap[word_idx] |= 1u64 << bit_idx;
            }
        }
    }
    
    /// Mark pages as free in bitmap
    fn mark_pages_free(&self, addr: PhysAddr, page_count: usize) {
        let page_index = self.addr_to_page_index(addr);
        let mut bitmap = self.allocation_bitmap.lock();
        
        for i in 0..page_count {
            let idx = page_index + i;
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            
            if word_idx < bitmap.len() {
                bitmap[word_idx] &= !(1u64 << bit_idx);
            }
        }
    }
    
    /// Check if pages are allocated
    fn are_pages_allocated(&self, addr: PhysAddr, page_count: usize) -> bool {
        let page_index = self.addr_to_page_index(addr);
        let bitmap = self.allocation_bitmap.lock();
        
        for i in 0..page_count {
            let idx = page_index + i;
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            
            if word_idx >= bitmap.len() {
                return false;
            }
            
            if (bitmap[word_idx] & (1u64 << bit_idx)) == 0 {
                return false;
            }
        }
        
        true
    }
    
    /// Convert address to page index
    fn addr_to_page_index(&self, addr: PhysAddr) -> usize {
        ((addr.as_u64() - self.memory_start.as_u64()) / PAGE_SIZE as u64) as usize
    }
    
    /// Check if defragmentation is needed
    fn check_defragmentation_need(&self) {
        let free_pages = self.free_pages.load(Ordering::Relaxed);
        let fragmented_pages = self.count_fragmented_pages();
        
        if fragmented_pages > self.defrag_threshold {
            let current_time = crate::time::timestamp_millis();
            let last_defrag = self.last_defrag_time.load(Ordering::Relaxed);
            
            // Only defragment if it's been at least 1 second since last defrag
            if current_time - last_defrag > 1000 {
                self.defragment_memory();
                self.last_defrag_time.store(current_time, Ordering::Relaxed);
            }
        }
    }
    
    /// Count fragmented pages (free pages in small blocks)
    fn count_fragmented_pages(&self) -> usize {
        let mut fragmented = 0;
        
        // Pages in orders 0-3 are considered fragmented
        for order in 0..4.min(MAX_ORDER) {
            let count = self.free_lists[order].lock().len();
            fragmented += count * (1 << order);
        }
        
        fragmented
    }
    
    /// Perform memory defragmentation
    fn defragment_memory(&self) {
        self.fragmentation_events.fetch_add(1, Ordering::Relaxed);
        
        // Attempt to coalesce free blocks
        for order in 0..(MAX_ORDER - 1) {
            let mut free_list = self.free_lists[order].lock();
            let mut coalesced = Vec::new();
            
            while let Some(addr) = free_list.pop() {
                let buddy_addr = self.find_buddy_address(addr, order);
                
                if let Some(pos) = free_list.iter().position(|&a| a == buddy_addr) {
                    // Found buddy - coalesce
                    free_list.swap_remove(pos);
                    let coalesced_addr = if addr < buddy_addr { addr } else { buddy_addr };
                    coalesced.push(coalesced_addr);
                } else {
                    // No buddy found - keep in current order
                    free_list.push(addr);
                    break;
                }
            }
            
            drop(free_list);
            
            // Add coalesced blocks to higher order
            if !coalesced.is_empty() {
                let mut higher_list = self.free_lists[order + 1].lock();
                higher_list.extend(coalesced);
            }
        }
    }
    
    /// Find largest contiguous free block
    pub fn find_largest_free_block(&self) -> usize {
        for order in (0..MAX_ORDER).rev() {
            if !self.free_lists[order].lock().is_empty() {
                return (1 << order) * PAGE_SIZE;
            }
        }
        0
    }
    
    /// Get allocation statistics
    pub fn get_stats(&self) -> AllocationStats {
        let largest_free_block = self.find_largest_free_block();
        let allocated = self.allocated_pages.load(Ordering::Relaxed);
        let free = self.free_pages.load(Ordering::Relaxed);
        
        let fragmentation_ratio = if free > 0 {
            let fragmented = self.count_fragmented_pages();
            fragmented as f64 / free as f64
        } else {
            0.0
        };
        
        AllocationStats {
            total_pages: self.total_pages,
            allocated_pages: allocated,
            free_pages: free,
            allocation_count: self.allocation_count.load(Ordering::Relaxed),
            deallocation_count: self.deallocation_count.load(Ordering::Relaxed),
            fragmentation_events: self.fragmentation_events.load(Ordering::Relaxed),
            largest_free_block,
            fragmentation_ratio,
        }
    }
}

/// Global buddy allocator instance
static mut BUDDY_ALLOCATOR: Option<BuddyAllocator> = None;

/// Initialize robust page allocator
pub fn init_robust_allocator(memory_start: PhysAddr, memory_size: usize, regions: &[MemoryRegion]) -> Result<(), &'static str> {
    let allocator = BuddyAllocator::new(memory_start, memory_size)?;
    allocator.initialize(regions)?;
    
    unsafe {
        BUDDY_ALLOCATOR = Some(allocator);
    }
    
    Ok(())
}

/// Get robust allocator instance
pub fn get_robust_allocator() -> Option<&'static BuddyAllocator> {
    unsafe { BUDDY_ALLOCATOR.as_ref() }
}

/// Allocate pages using robust allocator
pub fn allocate_pages_robust(page_count: usize) -> Option<PhysAddr> {
    get_robust_allocator()?.allocate_pages(page_count)
}

/// Deallocate pages using robust allocator
pub fn deallocate_pages_robust(addr: PhysAddr, page_count: usize) -> Result<(), &'static str> {
    get_robust_allocator()
        .ok_or("Robust allocator not initialized")?
        .deallocate_pages(addr, page_count)
}

/// Allocate single page using robust allocator
pub fn allocate_page_robust() -> Option<PhysAddr> {
    allocate_pages_robust(1)
}

/// Deallocate single page using robust allocator
pub fn deallocate_page_robust(addr: PhysAddr) -> Result<(), &'static str> {
    deallocate_pages_robust(addr, 1)
}