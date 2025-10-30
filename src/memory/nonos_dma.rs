#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering, compiler_fence};
use core::ptr;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::nonos_layout as layout;
use crate::memory::nonos_frame_alloc as frame_alloc;

static DMA_ALLOCATOR: Mutex<DmaAllocator> = Mutex::new(DmaAllocator::new());
static DMA_STATS: DmaStats = DmaStats::new();

struct DmaAllocator {
    coherent_regions: BTreeMap<VirtAddr, DmaRegion>,
    streaming_mappings: BTreeMap<u64, StreamingMapping>,
    next_vaddr: u64,
    next_mapping_id: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct DmaRegion {
    pub virt_addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
    pub coherent: bool,
    pub dma32_compatible: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct StreamingMapping {
    pub mapping_id: u64,
    pub buffer_va: VirtAddr,
    pub dma_addr: PhysAddr,
    pub size: usize,
    pub direction: DmaDirection,
    pub bounce_buffer: Option<DmaRegion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    ToDevice,
    FromDevice,
    Bidirectional,
}

#[derive(Debug, Clone, Copy)]
pub struct DmaConstraints {
    pub alignment: usize,
    pub max_segment_size: usize,
    pub dma32_only: bool,
    pub coherent: bool,
}

impl Default for DmaConstraints {
    fn default() -> Self {
        Self {
            alignment: layout::PAGE_SIZE,
            max_segment_size: 1024 * 1024,
            dma32_only: false,
            coherent: true,
        }
    }
}

pub struct DmaPool {
    regions: Vec<DmaRegion>,
    free_regions: Vec<usize>,
    constraints: DmaConstraints,
    total_size: usize,
    allocated_count: usize,
}

impl DmaPool {
    pub fn new(region_size: usize, capacity: usize, constraints: DmaConstraints) -> Result<Self, &'static str> {
        Ok(Self {
            regions: Vec::with_capacity(capacity),
            free_regions: Vec::with_capacity(capacity),
            constraints,
            total_size: region_size * capacity,
            allocated_count: 0,
        })
    }

    pub fn add_region(&mut self, region: DmaRegion) -> Result<(), &'static str> {
        if self.regions.len() >= self.regions.capacity() {
            return Err("DMA pool at capacity");
        }
        
        let index = self.regions.len();
        self.regions.push(region);
        self.free_regions.push(index);
        Ok(())
    }

    pub fn allocate(&mut self) -> Option<DmaRegion> {
        if let Some(index) = self.free_regions.pop() {
            self.allocated_count += 1;
            Some(self.regions[index])
        } else {
            None
        }
    }

    pub fn deallocate(&mut self, region: DmaRegion) -> Result<(), &'static str> {
        for (index, &stored_region) in self.regions.iter().enumerate() {
            if stored_region.virt_addr == region.virt_addr && 
               stored_region.phys_addr == region.phys_addr {
                if !self.free_regions.contains(&index) {
                    self.free_regions.push(index);
                    self.allocated_count -= 1;
                    return Ok(());
                } else {
                    return Err("Double free detected");
                }
            }
        }
        Err("Region not found in pool")
    }

    pub fn available(&self) -> usize {
        self.free_regions.len()
    }

    pub fn allocated(&self) -> usize {
        self.allocated_count
    }
}

struct DmaStats {
    coherent_allocations: AtomicUsize,
    streaming_mappings: AtomicUsize,
    bounce_buffer_usage: AtomicUsize,
    total_dma_memory: AtomicU64,
    dma_operations: AtomicU64,
}

impl DmaStats {
    const fn new() -> Self {
        Self {
            coherent_allocations: AtomicUsize::new(0),
            streaming_mappings: AtomicUsize::new(0),
            bounce_buffer_usage: AtomicUsize::new(0),
            total_dma_memory: AtomicU64::new(0),
            dma_operations: AtomicU64::new(0),
        }
    }

    fn record_coherent_alloc(&self, size: usize) {
        self.coherent_allocations.fetch_add(1, Ordering::Relaxed);
        self.total_dma_memory.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn record_coherent_free(&self, size: usize) {
        self.coherent_allocations.fetch_sub(1, Ordering::Relaxed);
        self.total_dma_memory.fetch_sub(size as u64, Ordering::Relaxed);
    }

    fn record_streaming_map(&self) {
        self.streaming_mappings.fetch_add(1, Ordering::Relaxed);
        self.dma_operations.fetch_add(1, Ordering::Relaxed);
    }

    fn record_streaming_unmap(&self) {
        self.streaming_mappings.fetch_sub(1, Ordering::Relaxed);
    }

    fn record_bounce_usage(&self, used: bool) {
        if used {
            self.bounce_buffer_usage.fetch_add(1, Ordering::Relaxed);
        } else {
            self.bounce_buffer_usage.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl DmaAllocator {
    const fn new() -> Self {
        Self {
            coherent_regions: BTreeMap::new(),
            streaming_mappings: BTreeMap::new(),
            next_vaddr: layout::DMA_BASE,
            next_mapping_id: 1,
            initialized: false,
        }
    }

    fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }

        self.next_vaddr = layout::DMA_BASE;
        self.coherent_regions.clear();
        self.streaming_mappings.clear();
        self.next_mapping_id = 1;
        self.initialized = true;

        Ok(())
    }

    fn allocate_coherent(&mut self, size: usize, constraints: DmaConstraints) -> Result<DmaRegion, &'static str> {
        if !self.initialized {
            return Err("DMA allocator not initialized");
        }

        if size == 0 {
            return Err("Invalid allocation size");
        }

        let aligned_size = self.align_up(size, constraints.alignment);
        let page_count = (aligned_size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;

        let virt_addr = self.allocate_virtual_range(aligned_size)?;
        
        let mut allocated_frames = Vec::new();
        
        for i in 0..page_count {
            let frame = frame_alloc::allocate_frame()
                .ok_or("Failed to allocate physical frame")?;
            
            if constraints.dma32_only && frame.as_u64() >= (1u64 << 32) {
                for prev_frame in allocated_frames {
                    frame_alloc::deallocate_frame(prev_frame);
                }
                return Err("DMA32 constraint not satisfied");
            }
            
            allocated_frames.push(frame);
        }

        let phys_addr = allocated_frames[0];
        
        for (i, frame) in allocated_frames.iter().enumerate() {
            let page_vaddr = VirtAddr::new(virt_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
            self.map_dma_page(page_vaddr, *frame, constraints.coherent)?;
        }

        let region = DmaRegion {
            virt_addr,
            phys_addr,
            size: aligned_size,
            coherent: constraints.coherent,
            dma32_compatible: constraints.dma32_only,
        };

        self.coherent_regions.insert(virt_addr, region);
        DMA_STATS.record_coherent_alloc(aligned_size);

        unsafe {
            ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, aligned_size);
        }

        Ok(region)
    }

    fn free_coherent(&mut self, virt_addr: VirtAddr) -> Result<(), &'static str> {
        let region = self.coherent_regions.remove(&virt_addr)
            .ok_or("DMA region not found")?;

        let page_count = (region.size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;

        for i in 0..page_count {
            let page_vaddr = VirtAddr::new(virt_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
            let phys_addr = PhysAddr::new(region.phys_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
            
            self.unmap_dma_page(page_vaddr)?;
            frame_alloc::deallocate_frame(phys_addr);
        }

        DMA_STATS.record_coherent_free(region.size);

        Ok(())
    }

    fn map_streaming(&mut self, buffer_va: VirtAddr, size: usize, direction: DmaDirection, constraints: DmaConstraints) -> Result<u64, &'static str> {
        let mapping_id = self.next_mapping_id;
        self.next_mapping_id += 1;

        let needs_bounce = self.needs_bounce_buffer(buffer_va, size, &constraints)?;
        
        let (dma_addr, bounce_buffer) = if needs_bounce {
            let bounce_region = self.allocate_coherent(size, constraints)?;
            
            if matches!(direction, DmaDirection::ToDevice | DmaDirection::Bidirectional) {
                self.copy_to_bounce_buffer(buffer_va, bounce_region.virt_addr, size)?;
            }
            
            DMA_STATS.record_bounce_usage(true);
            (bounce_region.phys_addr, Some(bounce_region))
        } else {
            let dma_addr = self.translate_to_physical(buffer_va)?;
            (dma_addr, None)
        };

        let mapping = StreamingMapping {
            mapping_id,
            buffer_va,
            dma_addr,
            size,
            direction,
            bounce_buffer,
        };

        self.streaming_mappings.insert(mapping_id, mapping);
        DMA_STATS.record_streaming_map();

        Ok(mapping_id)
    }

    fn unmap_streaming(&mut self, mapping_id: u64) -> Result<(), &'static str> {
        let mapping = self.streaming_mappings.remove(&mapping_id)
            .ok_or("Streaming mapping not found")?;

        if let Some(bounce_region) = mapping.bounce_buffer {
            if matches!(mapping.direction, DmaDirection::FromDevice | DmaDirection::Bidirectional) {
                self.copy_from_bounce_buffer(bounce_region.virt_addr, mapping.buffer_va, mapping.size)?;
            }
            
            self.free_coherent(bounce_region.virt_addr)?;
            DMA_STATS.record_bounce_usage(false);
        }

        DMA_STATS.record_streaming_unmap();

        Ok(())
    }

    fn allocate_virtual_range(&mut self, size: usize) -> Result<VirtAddr, &'static str> {
        let aligned_size = self.align_up(size, layout::PAGE_SIZE);
        let aligned_addr = self.align_up(self.next_vaddr as usize, layout::PAGE_SIZE) as u64;

        if aligned_addr + aligned_size as u64 > layout::DMA_BASE + layout::DMA_SIZE {
            return Err("DMA virtual address space exhausted");
        }

        let virt_addr = VirtAddr::new(aligned_addr);
        self.next_vaddr = aligned_addr + aligned_size as u64;

        Ok(virt_addr)
    }

    fn map_dma_page(&self, virt_addr: VirtAddr, phys_addr: PhysAddr, coherent: bool) -> Result<(), &'static str> {
        use crate::memory::nonos_virt;

        let mut flags = 0x03;
        if !coherent {
            flags |= 0x10;
        }

        unsafe {
            nonos_virt::map_page_4k(virt_addr, phys_addr, true, false, false)
                .map_err(|_| "Failed to map DMA page")?;
        }

        if coherent {
            compiler_fence(Ordering::SeqCst);
        }

        Ok(())
    }

    fn unmap_dma_page(&self, virt_addr: VirtAddr) -> Result<(), &'static str> {
        use crate::memory::nonos_virt;

        unsafe {
            nonos_virt::unmap_page(virt_addr)
                .map_err(|_| "Failed to unmap DMA page")?;
        }

        Ok(())
    }

    fn needs_bounce_buffer(&self, buffer_va: VirtAddr, size: usize, constraints: &DmaConstraints) -> Result<bool, &'static str> {
        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        let mut current_va = buffer_va;

        for _ in 0..page_count {
            let phys_addr = self.translate_to_physical(current_va)?;
            
            if constraints.dma32_only && phys_addr.as_u64() >= (1u64 << 32) {
                return Ok(true);
            }
            
            if phys_addr.as_u64() % constraints.alignment as u64 != 0 {
                return Ok(true);
            }
            
            current_va = VirtAddr::new(current_va.as_u64() + layout::PAGE_SIZE as u64);
        }

        Ok(false)
    }

    fn translate_to_physical(&self, virt_addr: VirtAddr) -> Result<PhysAddr, &'static str> {
        use crate::memory::nonos_virt;

        unsafe {
            nonos_virt::translate_addr(virt_addr).map_err(|_| "Address translation failed")
        }
    }

    fn copy_to_bounce_buffer(&self, src_va: VirtAddr, dst_va: VirtAddr, size: usize) -> Result<(), &'static str> {
        unsafe {
            let src = core::slice::from_raw_parts(src_va.as_ptr::<u8>(), size);
            let dst = core::slice::from_raw_parts_mut(dst_va.as_mut_ptr::<u8>(), size);
            dst.copy_from_slice(src);
        }
        Ok(())
    }

    fn copy_from_bounce_buffer(&self, src_va: VirtAddr, dst_va: VirtAddr, size: usize) -> Result<(), &'static str> {
        unsafe {
            let src = core::slice::from_raw_parts(src_va.as_ptr::<u8>(), size);
            let dst = core::slice::from_raw_parts_mut(dst_va.as_mut_ptr::<u8>(), size);
            dst.copy_from_slice(src);
        }
        Ok(())
    }

    const fn align_up(&self, value: usize, align: usize) -> usize {
        (value + align - 1) & !(align - 1)
    }
}

pub fn init() -> Result<(), &'static str> {
    let mut allocator = DMA_ALLOCATOR.lock();
    allocator.init()
}

pub fn alloc_coherent(size: usize, constraints: DmaConstraints) -> Result<DmaRegion, &'static str> {
    let mut allocator = DMA_ALLOCATOR.lock();
    allocator.allocate_coherent(size, constraints)
}

pub fn alloc_coherent_safe(size: usize, constraints: DmaConstraints) -> Result<DmaRegion, &'static str> {
    alloc_coherent(size, constraints)
}

pub fn alloc_coherent_dma32(size: usize) -> Result<DmaRegion, &'static str> {
    let constraints = DmaConstraints {
        dma32_only: true,
        ..DmaConstraints::default()
    };
    alloc_coherent(size, constraints)
}

pub fn free_coherent(virt_addr: VirtAddr) -> Result<(), &'static str> {
    let mut allocator = DMA_ALLOCATOR.lock();
    allocator.free_coherent(virt_addr)
}

pub fn map_streaming(buffer_va: VirtAddr, size: usize, direction: DmaDirection, constraints: DmaConstraints) -> Result<u64, &'static str> {
    let mut allocator = DMA_ALLOCATOR.lock();
    allocator.map_streaming(buffer_va, size, direction, constraints)
}

pub fn map_streaming_safe(buffer_va: VirtAddr, size: usize, direction: DmaDirection, constraints: DmaConstraints) -> Result<u64, &'static str> {
    map_streaming(buffer_va, size, direction, constraints)
}

pub fn unmap_streaming(mapping_id: u64) -> Result<(), &'static str> {
    let mut allocator = DMA_ALLOCATOR.lock();
    allocator.unmap_streaming(mapping_id)
}

pub fn get_mapping_info(mapping_id: u64) -> Option<StreamingMapping> {
    let allocator = DMA_ALLOCATOR.lock();
    allocator.streaming_mappings.get(&mapping_id).copied()
}

pub fn get_region_info(virt_addr: VirtAddr) -> Option<DmaRegion> {
    let allocator = DMA_ALLOCATOR.lock();
    allocator.coherent_regions.get(&virt_addr).copied()
}

pub fn sync_for_device(mapping_id: u64) -> Result<(), &'static str> {
    let allocator = DMA_ALLOCATOR.lock();
    let mapping = allocator.streaming_mappings.get(&mapping_id)
        .ok_or("Streaming mapping not found")?;

    if let Some(bounce_region) = mapping.bounce_buffer {
        if matches!(mapping.direction, DmaDirection::ToDevice | DmaDirection::Bidirectional) {
            unsafe {
                let src = core::slice::from_raw_parts(mapping.buffer_va.as_ptr::<u8>(), mapping.size);
                let dst = core::slice::from_raw_parts_mut(bounce_region.virt_addr.as_mut_ptr::<u8>(), mapping.size);
                dst.copy_from_slice(src);
            }
        }
    }

    compiler_fence(Ordering::SeqCst);
    Ok(())
}

pub fn sync_for_cpu(mapping_id: u64) -> Result<(), &'static str> {
    let allocator = DMA_ALLOCATOR.lock();
    let mapping = allocator.streaming_mappings.get(&mapping_id)
        .ok_or("Streaming mapping not found")?;

    compiler_fence(Ordering::SeqCst);

    if let Some(bounce_region) = mapping.bounce_buffer {
        if matches!(mapping.direction, DmaDirection::FromDevice | DmaDirection::Bidirectional) {
            unsafe {
                let src = core::slice::from_raw_parts(bounce_region.virt_addr.as_ptr::<u8>(), mapping.size);
                let dst = core::slice::from_raw_parts_mut(mapping.buffer_va.as_mut_ptr::<u8>(), mapping.size);
                dst.copy_from_slice(src);
            }
        }
    }

    Ok(())
}

pub fn get_stats() -> DmaStatsSnapshot {
    DmaStatsSnapshot {
        coherent_allocations: DMA_STATS.coherent_allocations.load(Ordering::Relaxed),
        streaming_mappings: DMA_STATS.streaming_mappings.load(Ordering::Relaxed),
        bounce_buffer_usage: DMA_STATS.bounce_buffer_usage.load(Ordering::Relaxed),
        total_dma_memory: DMA_STATS.total_dma_memory.load(Ordering::Relaxed),
        dma_operations: DMA_STATS.dma_operations.load(Ordering::Relaxed),
    }
}

#[derive(Debug)]
pub struct DmaStatsSnapshot {
    pub coherent_allocations: usize,
    pub streaming_mappings: usize,
    pub bounce_buffer_usage: usize,
    pub total_dma_memory: u64,
    pub dma_operations: u64,
}

pub fn is_dma_region(virt_addr: VirtAddr) -> bool {
    let allocator = DMA_ALLOCATOR.lock();
    allocator.coherent_regions.contains_key(&virt_addr) ||
    allocator.streaming_mappings.values().any(|m| {
        if let Some(bounce) = m.bounce_buffer {
            bounce.virt_addr == virt_addr
        } else {
            false
        }
    })
}

pub fn validate_dma_address(dma_addr: PhysAddr, size: usize, dma32_only: bool) -> bool {
    if dma32_only && dma_addr.as_u64() + size as u64 > (1u64 << 32) {
        return false;
    }

    if dma_addr.as_u64() % layout::PAGE_SIZE as u64 != 0 {
        return false;
    }

    true
}

pub fn alloc_dma_coherent(size: usize, constraints: DmaConstraints) -> Result<DmaRegion, &'static str> {
    alloc_coherent(size, constraints)
}

/// Initialize DMA allocator (alias for init)
pub fn init_dma_allocator() -> Result<(), &'static str> {
    init()
}

pub fn create_dma_pool(size: usize, count: usize, constraints: DmaConstraints) -> Result<DmaPool, &'static str> {
    let mut pool = DmaPool::new(size, count, constraints)?;
    
    for _ in 0..count {
        match alloc_coherent(size, constraints) {
            Ok(region) => pool.add_region(region)?,
            Err(e) => return Err(e),
        }
    }
    
    Ok(pool)
}

pub fn get_allocated_regions() -> alloc::vec::Vec<DmaRegion> {
    let allocator = DMA_ALLOCATOR.lock();
    allocator.coherent_regions.values().copied().collect()
}