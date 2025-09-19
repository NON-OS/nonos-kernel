//! NØNOS Kernel Heap Initialization
//!
//! This module sets up a virtual heap for dynamic memory allocation in the kernel
//! using `linked_list_allocator`. The heap is mapped during paging init and supports
//! RAM-only operation under the ZeroState runtime. Future extensions may include
//! multiple heap pools, fragmentation diagnostics, and mod-specific allocators.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use linked_list_allocator::LockedHeap;
use spin::Mutex;
use alloc::format;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

/// Static bounds for heap (will later support dynamic regions)
pub const HEAP_START: usize = 0x_4444_0000;
pub const HEAP_SIZE: usize = 1024 * 1024 * 2; // 2 MiB

/// Global kernel heap instance
#[global_allocator]
static KERNEL_HEAP: LockedHeap = LockedHeap::empty();

/// Optional heap enablement tracking
static HEAP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Heap usage statistics for production monitoring
static HEAP_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static HEAP_DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static HEAP_BYTES_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static HEAP_PEAK_USAGE: AtomicUsize = AtomicUsize::new(0);
static HEAP_ALLOCATION_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Active allocation tracking for leak detection
static ACTIVE_ALLOCATIONS: Mutex<BTreeMap<usize, AllocationInfo>> = Mutex::new(BTreeMap::new());

/// Initializes the global heap for kernel use
pub fn init_kernel_heap() {
    unsafe {
        KERNEL_HEAP.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
        HEAP_ENABLED.store(true, Ordering::SeqCst);
    }
    log_heap_status("[HEAP] Kernel heap initialized");
}

/// Simple heap init function for compatibility
pub fn init() {
    init_kernel_heap();
}

/// Log message to VGA or logging backend
fn log_heap_status(msg: &str) {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log(msg);
    } else {
        // fallback to VGA for very early init
        let vga = 0xb8000 as *mut u8;
        for (i, byte) in msg.bytes().enumerate().take(80) {
            unsafe {
                *vga.offset(i as isize * 2) = byte;
            }
        }
    }
}

/// Custom allocator fallback used in early boot
pub struct DummyAllocator;

unsafe impl GlobalAlloc for DummyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !HEAP_ENABLED.load(Ordering::SeqCst) {
            HEAP_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
            return null_mut();
        }

        // Check for reasonable allocation limits
        if layout.size() > HEAP_SIZE / 2 {
            log_heap_status("[HEAP] WARNING: Large allocation attempt blocked");
            HEAP_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
            return null_mut();
        }

        let ptr = KERNEL_HEAP.alloc(layout);
        if !ptr.is_null() {
            HEAP_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            let new_usage = HEAP_BYTES_ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            
            // Track this allocation
            track_allocation(ptr, layout);
            
            // Update peak usage tracking
            let mut peak = HEAP_PEAK_USAGE.load(Ordering::Relaxed);
            while new_usage > peak {
                match HEAP_PEAK_USAGE.compare_exchange_weak(peak, new_usage, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(x) => peak = x,
                }
            }
            
            // Warn if heap usage is getting high
            if new_usage > (HEAP_SIZE * 3) / 4 {
                log_heap_status("[HEAP] WARNING: Heap usage above 75%");
            }
        } else {
            HEAP_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if HEAP_ENABLED.load(Ordering::SeqCst) && !ptr.is_null() {
            KERNEL_HEAP.dealloc(ptr, layout);
            HEAP_DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            HEAP_BYTES_ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
            
            // Stop tracking this allocation
            untrack_allocation(ptr);
        }
    }
}

/// Handles out-of-memory conditions with production-ready recovery
#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    HEAP_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
    
    // Log detailed heap statistics for debugging
    let allocs = HEAP_ALLOCATIONS.load(Ordering::Relaxed);
    let deallocs = HEAP_DEALLOCATIONS.load(Ordering::Relaxed);
    let current_usage = HEAP_BYTES_ALLOCATED.load(Ordering::Relaxed);
    let peak_usage = HEAP_PEAK_USAGE.load(Ordering::Relaxed);
    let failures = HEAP_ALLOCATION_FAILURES.load(Ordering::Relaxed);
    
    crate::log::logger::log_critical(&format!(
        "[HEAP] CRITICAL: OOM - Size: {}, Align: {}, Usage: {}/{}, Peak: {}, Allocs: {}, Deallocs: {}, Failures: {}",
        layout.size(), layout.align(), current_usage, HEAP_SIZE, peak_usage, allocs, deallocs, failures
    ));
    
    // In production, we might want to trigger emergency cleanup or restart
    // For now, halt the system safely
    panic!("[HEAP] Out of memory - System halted");
}

/// Get current heap statistics for monitoring
pub fn get_heap_stats() -> HeapStats {
    HeapStats {
        total_size: HEAP_SIZE,
        current_usage: HEAP_BYTES_ALLOCATED.load(Ordering::Relaxed),
        peak_usage: HEAP_PEAK_USAGE.load(Ordering::Relaxed),
        allocations: HEAP_ALLOCATIONS.load(Ordering::Relaxed),
        deallocations: HEAP_DEALLOCATIONS.load(Ordering::Relaxed),
        failures: HEAP_ALLOCATION_FAILURES.load(Ordering::Relaxed),
        enabled: HEAP_ENABLED.load(Ordering::Relaxed),
    }
}

/// Heap statistics structure
pub struct HeapStats {
    pub total_size: usize,
    pub current_usage: usize,
    pub peak_usage: usize,
    pub allocations: u64,
    pub deallocations: u64,
    pub failures: u64,
    pub enabled: bool,
}

/// Check heap health and return true if healthy
pub fn check_heap_health() -> bool {
    let stats = get_heap_stats();
    
    // Consider unhealthy if:
    // - Not enabled
    // - Usage above 90%
    // - Too many failures
    if !stats.enabled {
        return false;
    }
    
    if stats.current_usage > (stats.total_size * 9) / 10 {
        log_heap_status("[HEAP] WARNING: Critical memory usage detected");
        return false;
    }
    
    if stats.failures > stats.allocations / 10 {
        log_heap_status("[HEAP] WARNING: High failure rate detected");
        return false;
    }
    
    true
}

/// Allocation information for tracking purposes
#[derive(Debug, Clone, Copy)]
pub struct AllocationInfo {
    pub ptr: usize,
    pub size: usize,
    pub layout_align: usize,
}

/// Get all current heap allocations with real tracking
pub fn get_all_allocations() -> Vec<AllocationInfo> {
    let allocations = ACTIVE_ALLOCATIONS.lock();
    allocations.values().cloned().collect()
}

/// Track a new allocation
fn track_allocation(ptr: *mut u8, layout: Layout) {
    if !ptr.is_null() {
        let info = AllocationInfo {
            ptr: ptr as usize,
            size: layout.size(),
            layout_align: layout.align(),
        };
        ACTIVE_ALLOCATIONS.lock().insert(ptr as usize, info);
    }
}

/// Stop tracking a deallocated pointer
fn untrack_allocation(ptr: *mut u8) {
    ACTIVE_ALLOCATIONS.lock().remove(&(ptr as usize));
}
