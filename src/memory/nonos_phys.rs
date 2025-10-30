#![no_std]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::ptr;
use spin::Mutex;
use x86_64::PhysAddr;
use crate::memory::nonos_layout as layout;

bitflags::bitflags! {
    pub struct AllocFlags: u32 {
        const EMPTY = 0;
        const ZERO  = 1 << 0;
        const HIGH  = 1 << 1;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Frame(pub u64);

#[derive(Clone, Copy, Debug)]
pub struct ZoneStats {
    pub frames_total: usize,
    pub frames_free: usize,
}

static FRAME_START: AtomicU64 = AtomicU64::new(0);
static FRAME_COUNT: AtomicUsize = AtomicUsize::new(0);
static BITMAP_PTR: AtomicU64 = AtomicU64::new(0);
static BITMAP_BYTES: AtomicUsize = AtomicUsize::new(0);
static NEXT_HINT: AtomicU64 = AtomicU64::new(0);
static NEXT_RAND: AtomicU64 = AtomicU64::new(0);
static LOCK: Mutex<()> = Mutex::new(());

fn bit_test(ptr: *mut u8, idx: usize) -> bool {
    unsafe {
        let byte = ptr.add(idx / 8).read_volatile();
        (byte & (1u8 << (idx & 7))) != 0
    }
}

fn bit_set(ptr: *mut u8, idx: usize) {
    unsafe {
        let bptr = ptr.add(idx / 8);
        let v = bptr.read_volatile();
        bptr.write_volatile(v | (1u8 << (idx & 7)));
    }
}

fn bit_clear(ptr: *mut u8, idx: usize) {
    unsafe {
        let bptr = ptr.add(idx / 8);
        let v = bptr.read_volatile();
        bptr.write_volatile(v & !(1u8 << (idx & 7)));
    }
}

pub fn init_with_bitmap(managed_start: PhysAddr, managed_end: PhysAddr, bitmap_ptr: *mut u8, bitmap_bytes: usize) -> Result<(), &'static str> {
    if managed_end.as_u64() <= managed_start.as_u64() { 
        return Err("Physical memory range invalid: end <= start"); 
    }
    
    let aligned_start = align_up(managed_start.as_u64(), layout::PAGE_SIZE as u64);
    let aligned_end = align_down(managed_end.as_u64(), layout::PAGE_SIZE as u64);
    
    if aligned_end <= aligned_start { 
        return Err("No complete pages in range after alignment"); 
    }
    
    let frame_count = ((aligned_end - aligned_start) / layout::PAGE_SIZE as u64) as usize;
    let required_bytes = (frame_count + 7) / 8;
    
    if bitmap_bytes < required_bytes { 
        return Err("Bitmap too small for managed memory range"); 
    }
    
    if bitmap_ptr.is_null() {
        return Err("Invalid bitmap pointer");
    }
    
    FRAME_START.store(aligned_start, Ordering::SeqCst);
    FRAME_COUNT.store(frame_count, Ordering::SeqCst);
    BITMAP_PTR.store(bitmap_ptr as u64, Ordering::SeqCst);
    BITMAP_BYTES.store(bitmap_bytes, Ordering::SeqCst);
    NEXT_HINT.store(0, Ordering::SeqCst);
    
    let seed = derive_seed();
    NEXT_RAND.store(seed, Ordering::Relaxed);
    
    unsafe { 
        ptr::write_bytes(bitmap_ptr, 0, required_bytes); 
    }
    
    Ok(())
}

pub fn total_memory() -> u64 {
    let frame_count = FRAME_COUNT.load(Ordering::Relaxed);
    (frame_count * layout::PAGE_SIZE) as u64
}

pub fn init(managed_start: PhysAddr, managed_end: PhysAddr) -> Result<(), &'static str> {
    let size = ((managed_end.as_u64().saturating_sub(managed_start.as_u64())) as usize / layout::PAGE_SIZE) + 8;
    let bytes = (size + 7) / 8;
    let mut v = alloc::vec::Vec::new();
    v.resize(bytes, 0u8);
    let bptr = v.leak().as_mut_ptr();
    init_with_bitmap(managed_start, managed_end, bptr, bytes)
}

fn derive_seed() -> u64 {
    if let Ok(nonce) = crate::memory::nonos_kaslr::boot_nonce() {
        nonce.wrapping_add(0x9e3779b97f4a7c15u64)
    } else {
        0x1337deadbeef4242u64
    }
}

fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
    z ^ (z >> 31)
}

pub fn allocate_frame(flags: AllocFlags) -> Option<Frame> {
    let _guard = LOCK.lock();
    
    let start = FRAME_START.load(Ordering::SeqCst);
    let total = FRAME_COUNT.load(Ordering::SeqCst);
    
    if total == 0 { 
        return None; 
    }
    
    let bptr = BITMAP_PTR.load(Ordering::SeqCst) as *mut u8;
    if bptr.is_null() {
        return None;
    }
    
    let hint = NEXT_HINT.load(Ordering::SeqCst) as usize;
    
    if flags.contains(AllocFlags::HIGH) {
        for i in (0..total).rev() {
            if !bit_test(bptr, i) {
                bit_set(bptr, i);
                NEXT_HINT.store(i as u64, Ordering::SeqCst);
                
                let pa = start.wrapping_add((i as u64).wrapping_mul(layout::PAGE_SIZE as u64));
                let frame = Frame(pa);
                
                if flags.contains(AllocFlags::ZERO) { 
                    zero_frame(frame); 
                }
                
                return Some(frame);
            }
        }
        return None;
    }
    
    let rnd = NEXT_RAND.fetch_add(1, Ordering::Relaxed);
    let idx0 = (mix64(rnd) as usize).wrapping_add(hint) % total;
    
    for off in 0..total {
        let i = (idx0 + off) % total;
        if !bit_test(bptr, i) {
            bit_set(bptr, i);
            NEXT_HINT.store(i as u64, Ordering::SeqCst);
            
            let pa = start.wrapping_add((i as u64).wrapping_mul(layout::PAGE_SIZE as u64));
            let frame = Frame(pa);
            
            if flags.contains(AllocFlags::ZERO) { 
                zero_frame(frame); 
            }
            
            return Some(frame);
        }
    }
    
    None
}

pub fn deallocate_frame(frame: Frame) -> Result<(), &'static str> {
    let _guard = LOCK.lock();
    
    let start = FRAME_START.load(Ordering::SeqCst);
    let total = FRAME_COUNT.load(Ordering::SeqCst);
    
    if total == 0 { 
        return Err("Physical memory allocator not initialized"); 
    }
    
    if frame.0 < start { 
        return Err("Frame address below managed range"); 
    }
    
    let offset = frame.0.saturating_sub(start);
    if offset % (layout::PAGE_SIZE as u64) != 0 {
        return Err("Frame address not page-aligned");
    }
    
    let idx = (offset / layout::PAGE_SIZE as u64) as usize;
    if idx >= total { 
        return Err("Frame address above managed range"); 
    }
    
    let bptr = BITMAP_PTR.load(Ordering::SeqCst) as *mut u8;
    if bptr.is_null() {
        return Err("Invalid bitmap pointer");
    }
    
    if !bit_test(bptr, idx) {
        return Err("Double free detected or frame not allocated");
    }
    
    bit_clear(bptr, idx);
    Ok(())
}

pub fn zone_stats() -> alloc::vec::Vec<(u32, ZoneStats)> {
    let total = FRAME_COUNT.load(Ordering::SeqCst);
    let bptr = BITMAP_PTR.load(Ordering::SeqCst) as *mut u8;
    
    if total == 0 || bptr.is_null() {
        return alloc::vec![(0, ZoneStats { frames_total: 0, frames_free: 0 })];
    }
    
    let mut free = 0usize;
    for i in 0..total {
        if !bit_test(bptr, i) { 
            free = free.saturating_add(1); 
        }
    }
    
    alloc::vec![(0, ZoneStats { frames_total: total, frames_free: free })]
}

pub fn total_free_frames() -> usize {
    let total = FRAME_COUNT.load(Ordering::SeqCst);
    let bptr = BITMAP_PTR.load(Ordering::SeqCst) as *mut u8;
    
    if total == 0 || bptr.is_null() {
        return 0;
    }
    
    let mut free = 0usize;
    for i in 0..total {
        if !bit_test(bptr, i) { 
            free = free.saturating_add(1); 
        }
    }
    free
}

pub fn alloc(flags: AllocFlags) -> Option<Frame> {
    allocate_frame(flags)
}

pub fn free(frame: Frame) -> Result<(), &'static str> {
    deallocate_frame(frame)
}

pub fn is_initialized() -> bool {
    FRAME_COUNT.load(Ordering::SeqCst) > 0 && BITMAP_PTR.load(Ordering::SeqCst) != 0
}

pub fn managed_range() -> (u64, u64) {
    let start = FRAME_START.load(Ordering::SeqCst);
    let count = FRAME_COUNT.load(Ordering::SeqCst);
    let end = start + ((count as u64) * layout::PAGE_SIZE as u64);
    (start, end)
}

fn align_up(x: u64, a: u64) -> u64 {
    ((x + a - 1) / a) * a
}

fn align_down(x: u64, a: u64) -> u64 {
    (x / a) * a
}

fn zero_frame(frame: Frame) {
    let pa = frame.0;
    let dm_base = layout::DIRECTMAP_BASE;
    let dm_size = layout::DIRECTMAP_SIZE;
    
    if pa >= dm_size { 
        return; 
    }
    
    let va = dm_base.wrapping_add(pa);
    if va < dm_base { 
        return; 
    }
    
    if va.wrapping_add(layout::PAGE_SIZE as u64) > dm_base.wrapping_add(dm_size) { 
        return; 
    }
    
    unsafe {
        let ptr = va as *mut u8;
        ptr::write_bytes(ptr, 0, layout::PAGE_SIZE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x86_64::PhysAddr;

    #[test]
    fn basic_init_alloc_free() {
        let start = PhysAddr::new(0x1000_0000);
        let end = PhysAddr::new(0x1000_0000 + 16 * 4096);
        let mut bitmap = [0u8; 2];
        init_with_bitmap(start, end, bitmap.as_mut_ptr(), bitmap.len()).expect("init");
        let f1 = allocate_frame(AllocFlags::EMPTY).expect("alloc1");
        let f2 = allocate_frame(AllocFlags::EMPTY).expect("alloc2");
        deallocate_frame(f1).expect("free1");
        deallocate_frame(f2).expect("free2");
    }

    #[test]
    fn double_free_detected() {
        let start = PhysAddr::new(0x2000_0000);
        let end = PhysAddr::new(0x2000_0000 + 8 * 4096);
        let mut bitmap = [0u8; 1];
        init_with_bitmap(start, end, bitmap.as_mut_ptr(), bitmap.len()).expect("init");
        let f = allocate_frame(AllocFlags::EMPTY).expect("alloc");
        deallocate_frame(f).expect("free");
        assert!(deallocate_frame(f).is_err());
    }
}