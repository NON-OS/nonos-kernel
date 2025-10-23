// Kernel heap with page-backed mapping, canary redzones, stats, and allocation tracking.

#![allow(dead_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{null_mut};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use linked_list_allocator::LockedHeap;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::virt::{self, VmFlags};
use crate::memory::nonos_phys as phys;
use crate::memory::layout::PAGE_SIZE;

#[derive(Debug, Clone)]
pub struct HeapStats {
    pub total_size: usize,
    pub current_usage: usize,
    pub peak_usage: usize,
    pub allocation_count: usize,
}

// Static heap window; mapped on init
pub const HEAP_START: usize = 0x_4444_0000;
pub const HEAP_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

// Underlying allocator backing store
static KERNEL_HEAP: LockedHeap = LockedHeap::empty();

// Global allocator wrapper with redzones/canaries/stats
#[global_allocator]
static GLOBAL_ALLOC: KernelAllocator = KernelAllocator;

static HEAP_ENABLED: AtomicBool = AtomicBool::new(false);
static HEAP_ZERO_ON_ALLOC: AtomicBool = AtomicBool::new(false);

static HEAP_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static HEAP_DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static HEAP_BYTES_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static HEAP_PEAK_USAGE: AtomicUsize = AtomicUsize::new(0);
static HEAP_ALLOCATION_FAILURES: AtomicU64 = AtomicU64::new(0);

// Live allocation map for diagnostics
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::format;
static ACTIVE_ALLOCATIONS: Mutex<BTreeMap<usize, AllocationInfo>> = Mutex::new(BTreeMap::new());

// Canary/redzone config
const REDZONE: usize = 32;
const CANARY: u64 = 0xC0DEC0DE_D15EA5E1;

#[repr(C)]
struct AllocHeader {
    total_size: usize, // full block given to underlying heap (including header/padding/redzones)
    payload_size: usize,
    align: usize,
    pad: usize,        // bytes from end-of-header to payload start before redzone
    canary: u64,
}

// Public API

pub fn init() { init_kernel_heap().expect("heap init failed"); }

pub fn init_heap() -> Result<(), &'static str> { init_kernel_heap() }

pub fn set_heap_zero_on_alloc(enable: bool) {
    HEAP_ZERO_ON_ALLOC.store(enable, Ordering::SeqCst);
}

pub fn init_kernel_heap() -> Result<(), &'static str> {
    map_kernel_heap_region(HEAP_START, HEAP_SIZE).map_err(|_| "heap map failed")?;
    unsafe {
        KERNEL_HEAP.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
    HEAP_ENABLED.store(true, Ordering::SeqCst);
    log_heap_status("[HEAP] online");
    Ok(())
}

pub fn get_heap_stats() -> HeapStats {
    HeapStats {
        total_size: HEAP_SIZE,
        current_usage: HEAP_BYTES_ALLOCATED.load(Ordering::Relaxed),
        peak_usage: HEAP_PEAK_USAGE.load(Ordering::Relaxed),
        allocation_count: HEAP_ALLOCATIONS.load(Ordering::Relaxed) as usize,
    }
}

pub fn check_heap_health() -> bool {
    let s = get_heap_stats();
    if s.total_size == 0 { return false; }
    if s.current_usage > (s.total_size * 9) / 10 { log_heap_status("[HEAP] high usage >90%"); return false; }
    if s.allocation_count == 0 { log_heap_status("[HEAP] no allocations"); return false; }
    true
}

#[derive(Debug, Clone, Copy)]
pub struct AllocationInfo {
    pub ptr: usize,
    pub size: usize,
    pub layout_align: usize,
}

pub fn get_all_allocations() -> Vec<AllocationInfo> {
    ACTIVE_ALLOCATIONS.lock().values().cloned().collect()
}

// Internals

fn map_kernel_heap_region(start: usize, size: usize) -> Result<(), ()> {
    let va0 = VirtAddr::new(start as u64);
    let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let flags = VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL;

    for i in 0..pages {
        let va = VirtAddr::new(va0.as_u64() + (i * PAGE_SIZE) as u64);
        let frame = phys::alloc(phys::AllocFlags::empty()).ok_or(())?;
        let pa = PhysAddr::new(frame.0);
        virt::map4k_at(va, pa, flags).map_err(|_| ())?;
    }
    Ok(())
}

fn log_heap_status(msg: &str) {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        if let Some(ref mut mgr) = *logger.lock() {
            mgr.log(crate::log::Severity::Err, msg);
        }
    }
}

// Allocation header/math

#[inline]
fn compute_layout_overhead(layout: Layout) -> (usize, usize) {
    let align = layout.align().max(core::mem::align_of::<AllocHeader>());
    let header = core::mem::size_of::<AllocHeader>();
    let after_header = (align - ((header) & (align - 1))) & (align - 1);
    // total = header + pad + REDZONE + payload + REDZONE
    let total = header + after_header + REDZONE + layout.size() + REDZONE;
    (align, total)
}

#[inline]
unsafe fn place_header_and_canaries(base: *mut u8, layout: Layout, align: usize, total: usize) -> *mut u8 {
    let header_ptr = base as *mut AllocHeader;
    let header_size = core::mem::size_of::<AllocHeader>();
    let pad = (align - (header_size & (align - 1))) & (align - 1);

    let payload = base.add(header_size + pad + REDZONE);
    // prefix canary occupies REDZONE bytes; fill as 8-byte chunks
    for off in (header_size + pad..header_size + pad + REDZONE).step_by(core::mem::size_of::<u64>()) {
        core::ptr::write_unaligned(base.add(off) as *mut u64, CANARY);
    }
    // suffix canary after payload
    let suffix_start = header_size + pad + REDZONE + layout.size();
    for off in (suffix_start..suffix_start + REDZONE).step_by(core::mem::size_of::<u64>()) {
        core::ptr::write_unaligned(base.add(off) as *mut u64, CANARY);
    }
    core::ptr::write(header_ptr, AllocHeader {
        total_size: total,
        payload_size: layout.size(),
        align,
        pad,
        canary: CANARY,
    });
    payload
}

#[inline]
unsafe fn validate_and_load_header(payload: *mut u8) -> (*mut u8, AllocHeader) {
    let header_size = core::mem::size_of::<AllocHeader>();
    // Find header by scanning back: payload - REDZONE - pad - header_size
    // We must read pad; but we need header to know pad. We stored a canary prefix pattern in redzone.
    // Use maximum pad bound (align_of::<AllocHeader>() <= 64 typical). We'll compute by trial from 0..align-1.
    // Simpler: store header pointer just before payload in the prefix redzone first 8 bytes.
    // For compatibility, compute it now:
    let meta_ptr_ptr = (payload as usize - 8) as *const u64;
    // If not initialized this way (legacy), fallback to best effort by scanning a few candidates.
    let header_ptr_guess = *(meta_ptr_ptr) as usize as *mut AllocHeader;

    let hdr = if header_ptr_guess as usize & 0x7 == 0 {
        // optimistic path
        core::ptr::read(header_ptr_guess)
    } else {
        // Fallback scan small range (up to 64 bytes)
        let mut found: Option<AllocHeader> = None;
        for pad in 0..64usize {
            let hp = (payload as usize - REDZONE - pad - header_size) as *const AllocHeader;
            let candidate = core::ptr::read(hp);
            if candidate.canary == CANARY && candidate.payload_size > 0 && candidate.total_size >= candidate.payload_size {
                found = Some(candidate);
                break;
            }
        }
        found.unwrap_or(AllocHeader { total_size: 0, payload_size: 0, align: 0, pad: 0, canary: 0 })
    };

    // Verify prefix redzone
    if hdr.canary == CANARY && hdr.total_size != 0 {
        let base = (payload as usize - (header_size + hdr.pad + REDZONE)) as *const u8;
        for off in (header_size + hdr.pad..header_size + hdr.pad + REDZONE).step_by(core::mem::size_of::<u64>()) {
            let v = core::ptr::read_unaligned(base.add(off) as *const u64);
            if v != CANARY { heap_corruption_panic("prefix canary"); }
        }
        // Verify suffix redzone
        let suffix = (payload as usize + hdr.payload_size) as *const u8;
        for off in (0..REDZONE).step_by(core::mem::size_of::<u64>()) {
            let v = core::ptr::read_unaligned(suffix.add(off) as *const u64);
            if v != CANARY { heap_corruption_panic("suffix canary"); }
        }
        let base_ptr = (payload as usize - (header_size + hdr.pad + REDZONE)) as *mut u8;
        (base_ptr, hdr)
    } else {
        heap_corruption_panic("invalid header");
        (core::ptr::null_mut(), hdr)
    }
}

#[inline]
fn heap_corruption_panic(where_: &str) -> ! {
    crate::log::logger::log_critical(&format!("[HEAP] corruption: {}", where_));
    panic!("[HEAP] corruption");
}

// Allocation tracking

fn track_allocation(ptr: *mut u8, layout: Layout) {
    if ptr.is_null() { return; }
    ACTIVE_ALLOCATIONS.lock().insert(ptr as usize, AllocationInfo {
        ptr: ptr as usize, size: layout.size(), layout_align: layout.align(),
    });
}

fn untrack_allocation(ptr: *mut u8) {
    ACTIVE_ALLOCATIONS.lock().remove(&(ptr as usize));
}

// Global allocator wrapper

pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !HEAP_ENABLED.load(Ordering::SeqCst) {
            HEAP_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
            return null_mut();
        }
        // bound very large requests
        if layout.size() > HEAP_SIZE / 2 {
            HEAP_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
            return null_mut();
        }

        let (align, total) = compute_layout_overhead(layout);
        let big_layout = Layout::from_size_align(total, align).unwrap();
        let base = KERNEL_HEAP.alloc(big_layout);
        if base.is_null() {
            HEAP_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
            return null_mut();
        }

        let payload = place_header_and_canaries(base, layout, align, total);

        if HEAP_ZERO_ON_ALLOC.load(Ordering::Relaxed) && layout.size() != 0 {
            core::ptr::write_bytes(payload, 0, layout.size());
        }

        HEAP_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        let new_usage = HEAP_BYTES_ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        // peak
        let mut peak = HEAP_PEAK_USAGE.load(Ordering::Relaxed);
        while new_usage > peak {
            match HEAP_PEAK_USAGE.compare_exchange_weak(peak, new_usage, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(x) => peak = x,
            }
        }

        track_allocation(payload, layout);

        payload
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }

        let (base, hdr) = validate_and_load_header(ptr);
        // erase redzones (optional)
        // copy header pointer into last 8 bytes of prefix redzone for faster lookup next time

        KERNEL_HEAP.dealloc(base, Layout::from_size_align(hdr.total_size, hdr.align).unwrap());

        HEAP_DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        HEAP_BYTES_ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);

        untrack_allocation(ptr);
    }
}

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    HEAP_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
    let s = get_heap_stats();
    crate::log::logger::log_critical(&format!(
        "[HEAP] OOM size={} align={} usage={}/{} peak={} allocs={}",
        layout.size(), layout.align(), s.current_usage, s.total_size, s.peak_usage, s.allocation_count
    ));
    panic!("[HEAP] OOM");
}
