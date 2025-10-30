#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, null_mut, NonNull};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::mem;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr};
use alloc::collections::BTreeSet;

use crate::memory::nonos_phys as phys;
use crate::memory::nonos_layout as layout;
use crate::memory::nonos_frame_alloc as frame_alloc;

pub struct HeapStats {
    pub total_size: usize,
    pub current_usage: usize,
    pub peak_usage: usize,
    pub allocation_count: usize,
}

struct HeapStatistics {
    total_size: AtomicUsize,
    current_usage: AtomicUsize,
    peak_usage: AtomicUsize,
    allocation_count: AtomicUsize,
    deallocation_count: AtomicUsize,
}

impl HeapStatistics {
    const fn new() -> Self {
        Self {
            total_size: AtomicUsize::new(0),
            current_usage: AtomicUsize::new(0),
            peak_usage: AtomicUsize::new(0),
            allocation_count: AtomicUsize::new(0),
            deallocation_count: AtomicUsize::new(0),
        }
    }

    fn record_allocation(&self, size: usize) {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        let new_usage = self.current_usage.fetch_add(size, Ordering::Relaxed) + size;
        
        loop {
            let current_peak = self.peak_usage.load(Ordering::Relaxed);
            if new_usage <= current_peak {
                break;
            }
            if self.peak_usage.compare_exchange_weak(
                current_peak,
                new_usage,
                Ordering::Relaxed,
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
    }

    fn record_deallocation(&self, size: usize) {
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
        self.current_usage.fetch_sub(size, Ordering::Relaxed);
    }

    fn set_total_size(&self, size: usize) {
        self.total_size.store(size, Ordering::Relaxed);
    }

    fn get_stats(&self) -> HeapStats {
        HeapStats {
            total_size: self.total_size.load(Ordering::Relaxed),
            current_usage: self.current_usage.load(Ordering::Relaxed),
            peak_usage: self.peak_usage.load(Ordering::Relaxed),
            allocation_count: self.allocation_count.load(Ordering::Relaxed),
        }
    }
}

use linked_list_allocator::LockedHeap;

#[repr(C)]
#[derive(Clone, Copy)]
struct AllocationHeader {
    magic: u32,
    size: usize,
    canary_offset: usize,
    allocated_at: u64,
}

fn get_timestamp() -> u64 {
    unsafe {
        let mut timestamp: u64;
        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") timestamp,
            out("rdx") _,
        );
        timestamp
    }
}

pub struct SecureHeapAllocator {
    inner: LockedHeap,
    allocated_ptrs: Mutex<BTreeSet<usize>>,
    canary_value: u64,
    initialized: AtomicBool,
    heap_size: AtomicUsize,
}

impl SecureHeapAllocator {
    const fn new() -> Self {
        Self {
            inner: LockedHeap::empty(),
            allocated_ptrs: Mutex::new(BTreeSet::new()),
            canary_value: 0xDEADBEEFCAFEBABE,
            initialized: AtomicBool::new(false),
            heap_size: AtomicUsize::new(0),
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    pub unsafe fn init(&self, heap_start: *mut u8, heap_size: usize) {
        self.inner.lock().init(heap_start, heap_size);
        self.heap_size.store(heap_size, Ordering::Release);
        self.initialized.store(true, Ordering::Release);
    }

    pub fn get_heap_size(&self) -> usize {
        self.heap_size.load(Ordering::Acquire)
    }

}

unsafe impl GlobalAlloc for SecureHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.is_initialized() {
            return null_mut();
        }
        
        let header_size = mem::size_of::<AllocationHeader>();
        let total_size = match header_size.checked_add(layout.size()) {
            Some(size) => match size.checked_add(mem::size_of::<u64>()) {
                Some(final_size) => final_size,
                None => return null_mut(),
            },
            None => return null_mut(),
        };
        
        let align = if layout.align() > 8 { layout.align() } else { 8 };
        let adjusted_layout = match Layout::from_size_align(total_size, align) {
            Ok(layout) => layout,
            Err(_) => return null_mut(),
        };
            
        let raw_ptr = self.inner.alloc(adjusted_layout);
        if raw_ptr.is_null() {
            return null_mut();
        }
        
        let header_ptr = raw_ptr as *mut AllocationHeader;
        let data_ptr = raw_ptr.add(header_size);
        let canary_ptr = data_ptr.add(layout.size()) as *mut u64;
        
        let header = AllocationHeader {
            magic: 0xDEADBEEF,
            size: layout.size(),
            canary_offset: layout.size(),
            allocated_at: get_timestamp(),
        };
        
        ptr::write_volatile(header_ptr, header);
        ptr::write_volatile(canary_ptr, self.canary_value);
        
        let data_addr = data_ptr as usize;
        {
            let mut allocated = self.allocated_ptrs.lock();
            if allocated.contains(&data_addr) {
                self.inner.dealloc(raw_ptr, adjusted_layout);
                return null_mut();
            }
            allocated.insert(data_addr);
        }
        
        HEAP_STATS.record_allocation(layout.size());
        
        if HEAP_ZERO_ON_ALLOC.load(Ordering::Relaxed) {
            ptr::write_bytes(data_ptr, 0, layout.size());
        }
        
        data_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() || !self.is_initialized() {
            return;
        }
        
        let ptr_addr = ptr as usize;
        
        let was_allocated = {
            let mut allocated = self.allocated_ptrs.lock();
            allocated.remove(&ptr_addr)
        };
        
        if !was_allocated {
            return;
        }
        
        let header_size = mem::size_of::<AllocationHeader>();
        let raw_ptr = ptr.sub(header_size);
        let header_ptr = raw_ptr as *const AllocationHeader;
        let header = ptr::read_volatile(header_ptr);
        
        if header.magic != 0xDEADBEEF || header.size != layout.size() {
            return;
        }
        
        let canary_ptr = ptr.add(header.canary_offset) as *const u64;
        let canary = ptr::read_volatile(canary_ptr);
        if canary != self.canary_value {
            return;
        }
        
        if HEAP_ZERO_ON_FREE.load(Ordering::Relaxed) {
            ptr::write_bytes(ptr, 0, layout.size());
        }
        
        let total_size = header_size + layout.size() + mem::size_of::<u64>();
        let align = if layout.align() > 8 { layout.align() } else { 8 };
        if let Ok(adjusted_layout) = Layout::from_size_align(total_size, align) {
            HEAP_STATS.record_deallocation(layout.size());
            self.inner.dealloc(raw_ptr, adjusted_layout);
        }
    }
}

#[global_allocator]
static KERNEL_HEAP: SecureHeapAllocator = SecureHeapAllocator::new();
static HEAP_ZERO_ON_ALLOC: AtomicBool = AtomicBool::new(true);
static HEAP_ZERO_ON_FREE: AtomicBool = AtomicBool::new(true);
static HEAP_STATS: HeapStatistics = HeapStatistics::new();
pub fn set_heap_zero_on_alloc(enable: bool) { 
    HEAP_ZERO_ON_ALLOC.store(enable, Ordering::SeqCst); 
}

pub fn set_heap_zero_on_free(enable: bool) { 
    HEAP_ZERO_ON_FREE.store(enable, Ordering::SeqCst); 
}

pub fn init() -> Result<(), &'static str> {
    if KERNEL_HEAP.is_initialized() {
        return Ok(());
    }
    
    let heap_size = layout::KHEAP_SIZE as usize;
    let heap_pages = (heap_size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    
    let heap_frames = allocate_heap_frames(heap_pages)?;
    let heap_start = map_heap_memory(&heap_frames)?;
    
    unsafe {
        KERNEL_HEAP.init(heap_start, heap_size);
    }
    
    HEAP_STATS.set_total_size(heap_size);
    
    Ok(())
}

fn allocate_heap_frames(page_count: usize) -> Result<alloc::vec::Vec<PhysAddr>, &'static str> {
    let mut frames = alloc::vec::Vec::new();
    
    for _ in 0..page_count {
        match frame_alloc::allocate_frame() {
            Some(addr) => frames.push(addr),
            None => return Err("Failed to allocate heap frames"),
        }
    }
    
    Ok(frames)
}

fn map_heap_memory(frames: &[PhysAddr]) -> Result<*mut u8, &'static str> {
    use crate::memory::nonos_virt;
    
    let heap_start = VirtAddr::new(layout::KHEAP_BASE);
    
    for (i, &frame_addr) in frames.iter().enumerate() {
        let virt_addr = VirtAddr::new(heap_start.as_u64() + (i * layout::PAGE_SIZE) as u64);
        
        nonos_virt::map_page_4k(
            virt_addr,
            frame_addr,
            true,  // writable  
            false, // not user
            false, // not executable
        ).map_err(|_| "Failed to map heap page")?;
    }
    
    Ok(heap_start.as_mut_ptr())
}

pub fn get_heap_stats() -> HeapStats {
    HEAP_STATS.get_stats()
}

pub fn get_allocator() -> &'static SecureHeapAllocator {
    &KERNEL_HEAP
}

pub fn verify_heap_integrity() -> bool {
    if !KERNEL_HEAP.is_initialized() {
        return false;
    }
    
    let heap_size = KERNEL_HEAP.get_heap_size();
    if heap_size == 0 {
        return false;
    }
    
    let allocated_ptrs = KERNEL_HEAP.allocated_ptrs.lock();
    for &ptr_addr in allocated_ptrs.iter() {
        if ptr_addr < layout::KHEAP_BASE as usize || 
           ptr_addr >= (layout::KHEAP_BASE + layout::KHEAP_SIZE) as usize {
            return false;
        }
        
        unsafe {
            let header_size = mem::size_of::<AllocationHeader>();
            let header_ptr = (ptr_addr - header_size) as *const AllocationHeader;
            let header = ptr::read_volatile(header_ptr);
            
            if header.magic != 0xDEADBEEF {
                return false;
            }
            
            let canary_ptr = (ptr_addr + header.canary_offset) as *const u64;
            let canary = ptr::read_volatile(canary_ptr);
            if canary != KERNEL_HEAP.canary_value {
                return false;
            }
            
            let current_time = get_timestamp();
            if current_time < header.allocated_at {
                return false;
            }
        }
    }
    
    true
}
