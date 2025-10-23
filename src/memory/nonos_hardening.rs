//! Memory Safety Hardening for NONOS Kernel

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use alloc::collections::BTreeMap;
use x86_64::VirtAddr;

use crate::memory::virt::{self, VmFlags};
use crate::memory::nonos_page_allocator as frame_alloc;
use crate::memory::layout::PAGE_SIZE;

// Stats
pub static MEMORY_STATS: MemoryStats = MemoryStats::new();

pub struct MemoryStats {
    pub guard_page_violations: AtomicU64,
    pub wx_violations: AtomicU64,
    pub stack_overflows_detected: AtomicU64,
    pub heap_corruptions_detected: AtomicU64,
    pub double_frees_prevented: AtomicU64,
    pub use_after_free_detected: AtomicU64,
    pub mapped_file_pages: AtomicU64,
    pub total_mapped_size: AtomicU64,
    pub kernel_mappings: AtomicU64,
}
impl MemoryStats {
    pub const fn new() -> Self {
        Self {
            guard_page_violations: AtomicU64::new(0),
            wx_violations: AtomicU64::new(0),
            stack_overflows_detected: AtomicU64::new(0),
            heap_corruptions_detected: AtomicU64::new(0),
            double_frees_prevented: AtomicU64::new(0),
            use_after_free_detected: AtomicU64::new(0),
            mapped_file_pages: AtomicU64::new(0),
            total_mapped_size: AtomicU64::new(0),
            kernel_mappings: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AllocationMetadata {
    pub base_addr: VirtAddr,
    pub size: usize, // payload bytes
    pub guard_before: VirtAddr,
    pub guard_after: VirtAddr,
    pub allocated_at: u64,
    pub magic: u64,
    pub checksum: u64,
}

static ALLOC_TRACK: Mutex<BTreeMap<u64, AllocationMetadata>> = Mutex::new(BTreeMap::new());

const HEAP_MAGIC_ALIVE: u64 = 0xDEADBEEFCAFEBABE;
static STACK_CANARY: AtomicU64 = AtomicU64::new(0);

// VA window for hardened allocations
const HWIN_BASE: u64 = 0xFFFF_8800_0000_0000;
const HWIN_END:  u64 = 0xFFFF_9000_0000_0000;
static NEXT_HWIN: AtomicU64 = AtomicU64::new(HWIN_BASE);

pub fn init_memory_hardening() -> Result<(), &'static str> {
    // Stack canary seed
    let mut canary = [0u8; 8];
    crate::crypto::vault::generate_random_bytes(&mut canary).map_err(|_| "rand failed")?;
    STACK_CANARY.store(u64::from_le_bytes(canary), Ordering::SeqCst);
    // SMEP/SMAP handled in MMU init; no duplication here.
    Ok(())
}

// Secure allocation with unmapped guard pages (no fake mappings).
pub fn secure_alloc(size: usize, align: usize) -> Result<VirtAddr, &'static str> {
    if size == 0 || !align.is_power_of_two() { return Err("invalid"); }
    let padded = (size + align - 1) & !(align - 1);
    let payload_pages = ((padded + PAGE_SIZE - 1) / PAGE_SIZE).max(1);
    let total_pages = payload_pages + 2; // 2 guards

    // Reserve VA window (no mapping for guard pages)
    let base = reserve_va(total_pages * PAGE_SIZE)?;
    let guard_before = base;
    let payload_base = VirtAddr::new(base.as_u64() + PAGE_SIZE as u64);
    let guard_after = VirtAddr::new(payload_base.as_u64() + (payload_pages * PAGE_SIZE) as u64);

    // Map payload pages RW+NX (W^X)
    for i in 0..payload_pages {
        let va = VirtAddr::new(payload_base.as_u64() + (i * PAGE_SIZE) as u64);
        let frame = frame_alloc::allocate_frame().ok_or("no frame")?;
        let pa = frame.start_address();
        virt::map4k_at(va, pa, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL).map_err(|_| "map fail")?;
    }

    // Metadata + canaries
    let md = AllocationMetadata {
        base_addr: payload_base,
        size: padded,
        guard_before,
        guard_after,
        allocated_at: timestamp_ms(),
        magic: HEAP_MAGIC_ALIVE,
        checksum: checksum(payload_base, padded),
    };
    ALLOC_TRACK.lock().insert(payload_base.as_u64(), md);

    unsafe { ptr::write_bytes(payload_base.as_mut_ptr::<u8>(), 0, padded); }
    add_canaries(payload_base, padded);

    Ok(payload_base)
}

pub fn secure_free(addr: VirtAddr) -> Result<(), &'static str> {
    let mut t = ALLOC_TRACK.lock();
    let md = t.remove(&addr.as_u64()).ok_or("untracked or double free")?;

    if md.magic != HEAP_MAGIC_ALIVE {
        MEMORY_STATS.use_after_free_detected.fetch_add(1, Ordering::SeqCst);
        return Err("use-after-free");
    }
    if !verify_canaries(md.base_addr, md.size) {
        MEMORY_STATS.heap_corruptions_detected.fetch_add(1, Ordering::SeqCst);
        return Err("heap corruption");
    }
    if md.checksum != checksum(md.base_addr, md.size) {
        MEMORY_STATS.heap_corruptions_detected.fetch_add(1, Ordering::SeqCst);
        return Err("metadata corruption");
    }

    // Zero payload then unmap frames page-by-page; we keep guards unmapped
    unsafe { ptr::write_bytes(md.base_addr.as_mut_ptr::<u8>(), 0, md.size); }

    let pages = ((md.size + PAGE_SIZE - 1) / PAGE_SIZE).max(1);
    for i in 0..pages {
        let va = VirtAddr::new(md.base_addr.as_u64() + (i * PAGE_SIZE) as u64);
        if let Ok((pa, _f, _sz)) = virt::translate(va) {
            virt::unmap4k(va).map_err(|_| "unmap")?;
            frame_alloc::deallocate_frame(x86_64::structures::paging::PhysFrame::containing_address(pa));
        }
    }

    Ok(())
}

// Toggle W^X: mark executable (no write)
pub fn make_executable(addr: VirtAddr, size: usize) -> Result<(), &'static str> {
    if size == 0 { return Ok(()); }
    protect_range(addr, size, VmFlags::GLOBAL) // RX: NX cleared by not setting it
}

// Toggle W^X: mark writable (NX)
pub fn make_writable(addr: VirtAddr, size: usize) -> Result<(), &'static str> {
    if size == 0 { return Ok(()); }
    protect_range(addr, size, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL)
}

fn protect_range(base: VirtAddr, size: usize, vmf: VmFlags) -> Result<(), &'static str> {
    let start = VirtAddr::new(base.as_u64() & !((PAGE_SIZE as u64) - 1));
    let end = base.as_u64() + size as u64;
    let len = ((end - start.as_u64() + (PAGE_SIZE as u64 - 1)) & !((PAGE_SIZE as u64) - 1)) as usize;
    crate::memory::virt::protect_range_4k(start, len, vmf).map_err(|_| "protect failed")
}

// Helpers

fn reserve_va(bytes: usize) -> Result<VirtAddr, &'static str> {
    use core::sync::atomic::AtomicU64;
    let bump = NEXT_HWIN.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
        let aligned = (cur + (PAGE_SIZE as u64 - 1)) & !((PAGE_SIZE as u64) - 1);
        let next = aligned.checked_add(bytes as u64)?;
        if next >= HWIN_END { None } else { Some(next) }
    }).map_err(|_| "VA window exhausted")?;
    Ok(VirtAddr::new((bump - bytes as u64)))
}

fn add_canaries(addr: VirtAddr, size: usize) {
    unsafe {
        let p = addr.as_mut_ptr::<u64>();
        *p = HEAP_MAGIC_ALIVE;
        if size >= 16 {
            let tail = (addr.as_u64() + size as u64 - 8) as *mut u64;
            *tail = HEAP_MAGIC_ALIVE;
        }
    }
}

fn verify_canaries(addr: VirtAddr, size: usize) -> bool {
    unsafe {
        if *(addr.as_ptr::<u64>()) != HEAP_MAGIC_ALIVE { return false; }
        if size >= 16 {
            let tail = (addr.as_u64() + size as u64 - 8) as *const u64;
            if *tail != HEAP_MAGIC_ALIVE { return false; }
        }
    }
    true
}

fn checksum(addr: VirtAddr, size: usize) -> u64 {
    addr.as_u64() ^ size as u64 ^ timestamp_ms()
}

#[inline]
fn timestamp_ms() -> u64 { crate::time::timestamp_millis() }
