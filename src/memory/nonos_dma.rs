//! DMA Memory Management
//!
//! Direct Memory Access (DMA) allocator for device drivers with 
//! physically contiguous memory allocation and cache coherency management.

use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use core::ptr;

/// DMA page allocation result
#[derive(Clone)]
pub struct DmaPage {
    pub virt_addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
}

impl DmaPage {
    /// Get physical address
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }
    
    /// Get virtual address
    pub fn virt_addr(&self) -> VirtAddr {
        self.virt_addr
    }
}

/// Physical address type for compatibility
pub type PhysicalAddress = PhysAddr;

/// DMA memory pool for managing physically contiguous allocations
struct DmaPool {
    free_pages: Vec<DmaPage>,
    allocated_pages: Vec<DmaPage>,
    total_size: usize,
    used_size: usize,
}

impl DmaPool {
    fn new() -> Self {
        Self {
            free_pages: Vec::new(),
            allocated_pages: Vec::new(),
            total_size: 0,
            used_size: 0,
        }
    }

    fn allocate(&mut self, size: usize) -> Result<DmaPage, &'static str> {
        // Round up to page size
        let aligned_size = (size + 4095) & !4095;

        // Try to find a suitable free page
        for (i, page) in self.free_pages.iter().enumerate() {
            if page.size >= aligned_size {
                let allocated_page = self.free_pages.remove(i);
                
                // If the page is larger than needed, split it
                if allocated_page.size > aligned_size {
                    let remaining_page = DmaPage {
                        virt_addr: allocated_page.virt_addr + aligned_size,
                        phys_addr: allocated_page.phys_addr + aligned_size,
                        size: allocated_page.size - aligned_size,
                    };
                    self.free_pages.push(remaining_page);
                }

                let result = DmaPage {
                    virt_addr: allocated_page.virt_addr,
                    phys_addr: allocated_page.phys_addr,
                    size: aligned_size,
                };

                self.allocated_pages.push(result.clone());
                self.used_size += aligned_size;
                
                return Ok(result);
            }
        }

        // No suitable free page found, allocate new memory
        self.allocate_new_page(aligned_size)
    }

    fn allocate_new_page(&mut self, size: usize) -> Result<DmaPage, &'static str> {
        // Use physical memory allocator to get physically contiguous pages
        let num_pages = (size + 4095) / 4096;
        
        // Allocate physical memory
        let phys_frame = crate::memory::phys::alloc_frames(num_pages)
            .ok_or("Failed to allocate physical memory")?;
        
        let phys_addr = PhysAddr::new(phys_frame * 4096);
        
        // Map physical memory to virtual address space
        let virt_addr = crate::memory::virt::map_physical_memory(phys_addr, size)
            .map_err(|_| "Failed to map DMA memory")?;

        let page = DmaPage {
            virt_addr,
            phys_addr,
            size,
        };

        self.allocated_pages.push(page.clone());
        self.total_size += size;
        self.used_size += size;

        Ok(page)
    }

    fn deallocate(&mut self, page: DmaPage) -> Result<(), &'static str> {
        // Find and remove from allocated pages
        let index = self.allocated_pages.iter().position(|p| {
            p.virt_addr == page.virt_addr && p.phys_addr == page.phys_addr
        }).ok_or("Page not found in allocated list")?;

        let _allocated_page = self.allocated_pages.remove(index);
        self.used_size -= page.size;

        // Zero out the memory for security
        unsafe {
            ptr::write_bytes(page.virt_addr.as_mut_ptr::<u8>(), 0, page.size);
        }

        // Add to free list
        self.free_pages.push(page);

        // Try to coalesce adjacent free pages
        self.coalesce_free_pages();

        Ok(())
    }

    fn coalesce_free_pages(&mut self) {
        // Sort free pages by virtual address
        self.free_pages.sort_by_key(|page| page.virt_addr);

        let mut i = 0;
        while i < self.free_pages.len().saturating_sub(1) {
            let current_end = self.free_pages[i].virt_addr + self.free_pages[i].size;
            let next_start = self.free_pages[i + 1].virt_addr;

            // Check if pages are adjacent
            if current_end == next_start {
                // Merge pages
                let next_page = self.free_pages.remove(i + 1);
                self.free_pages[i].size += next_page.size;
            } else {
                i += 1;
            }
        }
    }

    fn get_stats(&self) -> DmaStats {
        DmaStats {
            total_size: self.total_size,
            used_size: self.used_size,
            free_size: self.total_size - self.used_size,
            allocated_pages: self.allocated_pages.len(),
            free_pages: self.free_pages.len(),
        }
    }
}

/// DMA allocator statistics
#[derive(Debug, Clone, Copy)]
pub struct DmaStats {
    pub total_size: usize,
    pub used_size: usize,
    pub free_size: usize,
    pub allocated_pages: usize,
    pub free_pages: usize,
}

/// Global DMA allocator
static DMA_ALLOCATOR: Mutex<Option<DmaPool>> = Mutex::new(None);

/// Allocate DMA-coherent memory
pub fn alloc_dma_page(size: usize) -> Result<DmaPage, &'static str> {
    let mut guard = DMA_ALLOCATOR.lock();
    if guard.is_none() {
        return Err("DMA allocator not initialized");
    }
    guard.as_mut().unwrap().allocate(size)
}

/// Free DMA-coherent memory
pub fn free_dma_page(page: DmaPage) -> Result<(), &'static str> {
    let mut guard = DMA_ALLOCATOR.lock();
    if let Some(allocator) = guard.as_mut() {
        allocator.deallocate(page)
    } else {
        Err("DMA allocator not initialized")
    }
}

/// Allocate DMA buffer with specific alignment
pub fn alloc_dma_aligned(size: usize, alignment: usize) -> Result<DmaPage, &'static str> {
    if !alignment.is_power_of_two() {
        return Err("Alignment must be power of two");
    }

    // Allocate slightly larger buffer to accommodate alignment
    let padded_size = size + alignment - 1;
    let page = alloc_dma_page(padded_size)?;

    // Calculate aligned address
    let aligned_virt = VirtAddr::new((page.virt_addr.as_u64() + alignment as u64 - 1) & !(alignment as u64 - 1));
    let offset = aligned_virt.as_u64() - page.virt_addr.as_u64();
    let aligned_phys = PhysAddr::new(page.phys_addr.as_u64() + offset);

    Ok(DmaPage {
        virt_addr: aligned_virt,
        phys_addr: aligned_phys,
        size: size,
    })
}

/// Sync DMA buffer for device access (cache coherency)
pub fn sync_dma_for_device(page: &DmaPage) {
    // On x86_64, memory is coherent by default, but we might need
    // to flush write buffers for some devices
    unsafe {
        core::arch::asm!("mfence", options(nomem, nostack));
    }
}

/// Sync DMA buffer for CPU access (cache coherency)
pub fn sync_dma_for_cpu(page: &DmaPage) {
    // On x86_64, memory is coherent by default, but we might need
    // to invalidate caches in some cases
    unsafe {
        core::arch::asm!("mfence", options(nomem, nostack));
    }
}

/// Map device memory for MMIO access
pub fn map_device_memory(phys_addr: PhysAddr, size: usize) -> Result<VirtAddr, &'static str> {
    crate::memory::virt::map_physical_memory(phys_addr, size)
        .map_err(|_| "Failed to map device memory")
}

/// Unmap device memory
pub fn unmap_device_memory(virt_addr: VirtAddr, size: usize) -> Result<(), &'static str> {
    crate::memory::virt::unmap_memory(virt_addr, size)
        .map_err(|_| "Failed to unmap device memory")
}

/// Initialize DMA allocator with initial memory pool
pub fn init_dma_allocator() -> Result<(), &'static str> {
    let mut guard = DMA_ALLOCATOR.lock();
    let mut allocator = DmaPool::new();
    
    // Pre-allocate a pool of DMA memory
    const INITIAL_POOL_SIZE: usize = 16 * 1024 * 1024; // 16MB
    
    let initial_page = allocator.allocate_new_page(INITIAL_POOL_SIZE)?;
    allocator.free_pages.push(initial_page);
    allocator.used_size -= INITIAL_POOL_SIZE; // It's in free list, not allocated
    
    *guard = Some(allocator);
    
    crate::log::info!("DMA allocator initialized with {} bytes", INITIAL_POOL_SIZE);
    Ok(())
}

/// Get DMA allocator statistics
pub fn get_dma_stats() -> DmaStats {
    let guard = DMA_ALLOCATOR.lock();
    guard.as_ref().map_or(
        DmaStats {
            total_size: 0,
            used_size: 0,
            free_size: 0,
            allocated_pages: 0,
            free_pages: 0,
        },
        |a| a.get_stats()
    )
}

/// DMA bounce buffer for devices that can't access high memory
pub struct DmaBounceBuffer {
    low_page: DmaPage,
    high_buffer: Option<Vec<u8>>,
}

impl DmaBounceBuffer {
    /// Create a new bounce buffer
    pub fn new(size: usize) -> Result<Self, &'static str> {
        // Allocate DMA memory in low memory (< 4GB) for compatibility
        let low_page = alloc_dma_page(size)?;
        
        Ok(Self {
            low_page,
            high_buffer: None,
        })
    }

    /// Copy data from high memory buffer to low memory for DMA
    pub fn copy_to_device(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > self.low_page.size {
            return Err("Data too large for bounce buffer");
        }

        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.low_page.virt_addr.as_mut_ptr(),
                data.len()
            );
        }

        sync_dma_for_device(&self.low_page);
        Ok(())
    }

    /// Copy data from low memory DMA buffer back to high memory
    pub fn copy_from_device(&self, buffer: &mut [u8]) -> Result<(), &'static str> {
        if buffer.len() > self.low_page.size {
            return Err("Buffer too large for bounce buffer");
        }

        sync_dma_for_cpu(&self.low_page);

        unsafe {
            ptr::copy_nonoverlapping(
                self.low_page.virt_addr.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len()
            );
        }

        Ok(())
    }

    /// Get physical address of the low memory buffer
    pub fn phys_addr(&self) -> PhysAddr {
        self.low_page.phys_addr
    }

    /// Get size of the buffer
    pub fn size(&self) -> usize {
        self.low_page.size
    }
}

impl Drop for DmaBounceBuffer {
    fn drop(&mut self) {
        let _ = free_dma_page(self.low_page.clone());
    }
}

/// DMA scatter-gather list for complex transfers
pub struct DmaScatterGather {
    pub segments: Vec<DmaSegment>,
    pub total_size: usize,
}

/// DMA segment for scatter-gather operations
pub struct DmaSegment {
    pub page: DmaPage,
    pub offset: usize,
    pub length: usize,
}

impl DmaScatterGather {
    /// Create a new scatter-gather list
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
            total_size: 0,
        }
    }

    /// Add a segment to the scatter-gather list
    pub fn add_segment(&mut self, data: &[u8]) -> Result<(), &'static str> {
        let page = alloc_dma_page(data.len())?;
        
        // Copy data to DMA buffer
        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                page.virt_addr.as_mut_ptr(),
                data.len()
            );
        }

        sync_dma_for_device(&page);

        self.segments.push(DmaSegment {
            page,
            offset: 0,
            length: data.len(),
        });

        self.total_size += data.len();
        Ok(())
    }

    /// Get physical addresses for hardware scatter-gather
    pub fn get_physical_segments(&self) -> Vec<(PhysAddr, usize)> {
        self.segments.iter().map(|seg| {
            (seg.page.phys_addr + seg.offset, seg.length)
        }).collect()
    }
}

impl Drop for DmaScatterGather {
    fn drop(&mut self) {
        for segment in &self.segments {
            let _ = free_dma_page(segment.page.clone());
        }
    }
}