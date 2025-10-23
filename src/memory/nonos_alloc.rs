//! Kernel heap allocator (slab + VM) for NØNOS.

#![allow(dead_code)]

use core::{mem, ptr, cell::UnsafeCell};
use spin::{Lazy, Mutex};
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::layout::{PAGE_SIZE, KHEAP_BASE, KHEAP_SIZE};
use crate::memory::phys::{self, AllocFlags as PFlags, Frame};
use crate::memory::virt::{self, VmFlags};

const MAX_CPUS: usize = 64;

// Size classes (bytes)
const CLASSES: &[usize] = &[
    16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const CLASSES_LEN: usize = 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroPolicy {
    OnFree,
    OnAlloc,
    Never,
}

#[derive(Clone, Copy, Debug)]
pub struct HeapPolicy {
    pub zero: ZeroPolicy,
    pub guard_large: bool,
    pub prefer_lowmem: bool,
}

impl Default for HeapPolicy {
    fn default() -> Self {
        Self { zero: ZeroPolicy::OnFree, guard_large: true, prefer_lowmem: true }
    }
}

#[repr(C)]
struct Slab {
    class: u32,
    obj_size: u32,
    used: u32,
    cap: u32,
    free_head: u32,     // 0..cap-1 or 0xFFFF_FFFF if empty
    next: *mut Slab,    // intrusive list link
    base_va: VirtAddr,  // slab base VA (points to header)
    pages: u32,         // number of 4K pages backing this slab
}

struct Magazine {
    head: [*mut Slab; CLASSES_LEN],
}
impl Magazine {
    const fn new() -> Self { Self { head: [core::ptr::null_mut(); CLASSES_LEN] } }
}
unsafe impl Send for Magazine {}
unsafe impl Sync for Magazine {}

struct Heap {
    pol: HeapPolicy,
    mags: [UnsafeCell<Magazine>; MAX_CPUS],
    vm_cursor: UnsafeCell<u64>, // bump VA for large mappings inside KHEAP window
    alloc_small: core::sync::atomic::AtomicU64,
    free_small: core::sync::atomic::AtomicU64,
    alloc_large: core::sync::atomic::AtomicU64,
    free_large: core::sync::atomic::AtomicU64,
}
unsafe impl Sync for Heap {}

static HEAP: Lazy<Mutex<Heap>> = Lazy::new(|| {
    Mutex::new(Heap {
        pol: HeapPolicy::default(),
        mags: [const { UnsafeCell::new(Magazine::new()) }; MAX_CPUS],
        vm_cursor: UnsafeCell::new(KHEAP_BASE), // start at configured heap window
        alloc_small: 0u64.into(),
        free_small: 0u64.into(),
        alloc_large: 0u64.into(),
        free_large: 0u64.into(),
    })
});

#[inline]
fn cpu_id() -> usize {
    // Single-CPU bring-up default; replace when SMP CPU id is available.
    0
}

// Public API

pub fn init(policy: HeapPolicy) {
    let mut h = HEAP.lock();
    h.pol = policy;
}

/// Allocate `size` bytes; <= 64 KiB go to slab, larger go to VM mapping.
pub unsafe fn kmalloc(size: usize) -> *mut u8 {
    if size == 0 { return core::ptr::null_mut(); }
    if let Some((class, sz)) = class_for(size) {
        alloc_small(class, sz)
    } else {
        kalloc_large(size, 16, true)
    }
}

/// Allocate `size` bytes aligned to `align` (power-of-two). Falls back to VM if needed.
pub unsafe fn kalloc_aligned(size: usize, align: usize) -> *mut u8 {
    if size == 0 { return core::ptr::null_mut(); }
    if align.is_power_of_two() && align <= 65536 {
        if let Some((class, sz)) = class_for(size.max(align)) {
            return alloc_small(class, sz);
        }
    }
    kalloc_large(size, align.max(16), true)
}

/// Free a pointer returned by kmalloc/kalloc_aligned (size is required).
pub unsafe fn kfree(p: *mut u8, size: usize) {
    if p.is_null() { return; }
    if let Some((class, sz)) = class_for(size) {
        free_small(p, class, sz);
    } else {
        kfree_large(p, size);
    }
}

/// Allocate N 4K pages as anonymous kernel memory (optionally with guard pages).
pub unsafe fn kalloc_pages(pages: usize, flags: VmFlags) -> VirtAddr {
    if pages == 0 { return VirtAddr::zero(); }
    map_large_pages(pages, flags, HEAP.lock().pol.guard_large)
}

/// Free N 4K pages previously allocated with kalloc_pages.
pub unsafe fn kfree_pages(base: VirtAddr, pages: usize) {
    if pages == 0 { return; }
    unmap_large_pages(base, pages, HEAP.lock().pol.guard_large)
}

pub fn stats() -> (u64, u64, u64, u64) {
    let h = HEAP.lock();
    (
        h.alloc_small.load(core::sync::atomic::Ordering::Relaxed),
        h.free_small.load(core::sync::atomic::Ordering::Relaxed),
        h.alloc_large.load(core::sync::atomic::Ordering::Relaxed),
        h.free_large.load(core::sync::atomic::Ordering::Relaxed),
    )
}

// Small/medium path — magazines + slabs

#[inline]
fn class_for(n: usize) -> Option<(usize, usize)> {
    for (i, &c) in CLASSES.iter().enumerate() {
        if c >= n { return Some((i, c)); }
    }
    None
}

unsafe fn alloc_small(class: usize, sz: usize) -> *mut u8 {
    let h = HEAP.lock();
    let cpu = cpu_id();
    let mag = &mut *h.mags[cpu].get();

    // Fast path
    let head = mag.head[class];
    if !head.is_null() {
        if let Some(p) = carve_obj_from_slab(head, &h.pol) {
            h.alloc_small.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            return p;
        }
    }

    // Need a new slab
    let slab = new_slab(class, sz, &h.pol);
    if slab.is_null() { return core::ptr::null_mut(); }
    (*slab).next = head;
    mag.head[class] = slab;

    let p = carve_obj_from_slab(slab, &h.pol).unwrap_or(core::ptr::null_mut());
    h.alloc_small.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    p
}

unsafe fn free_small(p: *mut u8, class: usize, sz: usize) {
    let h = HEAP.lock();
    let cpu = cpu_id();
    let mag = &mut *h.mags[cpu].get();

    // Recover slab pointer stored just before payload
    let slab_ptr_slot = (p as usize - mem::size_of::<*mut Slab>()) as *const *mut Slab;
    let slab = *slab_ptr_slot;

    // Sanity: confirm class and bounds
    debug_assert!(!slab.is_null());
    debug_assert_eq!((*slab).obj_size as usize, sz);
    let idx = obj_index_in_slab(slab, p, sz);
    debug_assert!(idx < (*slab).cap);

    if matches!(h.pol.zero, ZeroPolicy::OnFree) {
        ptr::write_bytes(p, 0, sz);
    }

    // Push into freelist
    let head = (*slab).free_head;
    write_u32_at(slab, idx, head);
    (*slab).free_head = idx;
    (*slab).used = (*slab).used.saturating_sub(1);

    // Reclaim empty slabs (unlink and unmap)
    if (*slab).used == 0 {
        let mut prev: *mut Slab = core::ptr::null_mut();
        let mut cur = mag.head[class];
        while !cur.is_null() {
            if cur == slab {
                if prev.is_null() { mag.head[class] = (*cur).next; }
                else { (*prev).next = (*cur).next; }
                break;
            }
            prev = cur; cur = (*cur).next;
        }
        unmap_slab_pages(slab);
    }

    h.free_small.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

unsafe fn new_slab(class: usize, sz: usize, _pol: &HeapPolicy) -> *mut Slab {
    // Choose 1..16 pages to target reasonable object counts
    let mut pages = 1usize;
    while pages * PAGE_SIZE < (sz * 32 + mem::size_of::<Slab>() + 256) {
        pages *= 2;
        if pages >= 16 { break; }
    }

    let va = map_large_pages(pages, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL, false);
    if va.as_u64() == 0 { return core::ptr::null_mut(); }

    let hdr = va.as_u64() as *mut Slab;
    ptr::write_bytes(hdr as *mut u8, 0, mem::size_of::<Slab>());

    let slab_bytes = pages * PAGE_SIZE;
    let meta_off = mem::size_of::<Slab>();
    let area = slab_bytes - meta_off;

    // Each object: [*mut Slab backptr (8B)] [payload sz bytes] [next index u32 stored right after backptr]
    let stride = mem::size_of::<*mut Slab>() + sz;
    let cap = area / stride;

    (*hdr).class = class as u32;
    (*hdr).obj_size = sz as u32;
    (*hdr).used = 0;
    (*hdr).cap = cap as u32;
    (*hdr).free_head = 0;
    (*hdr).next = core::ptr::null_mut();
    (*hdr).base_va = VirtAddr::new(va.as_u64());
    (*hdr).pages = pages as u32;

    for i in 0..cap {
        let obj = obj_ptr(hdr, i, sz);
        *(obj as *mut *mut Slab) = hdr;
        let next = if i + 1 < cap { (i + 1) as u32 } else { 0xffff_ffff };
        let next_slot = obj.add(mem::size_of::<*mut Slab>()) as *mut u32;
        *next_slot = next;
    }

    hdr
}

#[inline]
unsafe fn carve_obj_from_slab(slab: *mut Slab, pol: &HeapPolicy) -> Option<*mut u8> {
    let head = (*slab).free_head;
    if head == 0xffff_ffff { return None; }
    let sz = (*slab).obj_size as usize;
    let obj = obj_ptr(slab, head as usize, sz);
    (*slab).free_head = read_u32_at(slab, head);
    (*slab).used = (*slab).used.saturating_add(1);
    let payload = obj.add(mem::size_of::<*mut Slab>());
    if matches!(pol.zero, ZeroPolicy::OnAlloc) {
        ptr::write_bytes(payload, 0, sz);
    }
    Some(payload)
}

#[inline]
unsafe fn obj_ptr(slab: *mut Slab, index: usize, sz: usize) -> *mut u8 {
    let base = (*slab).base_va.as_u64() as usize + mem::size_of::<Slab>();
    let stride = mem::size_of::<*mut Slab>() + sz;
    (base + index * stride) as *mut u8
}

#[inline]
unsafe fn obj_index_in_slab(slab: *mut Slab, payload: *mut u8, sz: usize) -> u32 {
    let base = (*slab).base_va.as_u64() as usize + mem::size_of::<Slab>();
    let stride = mem::size_of::<*mut Slab>() + sz;
    let obj = (payload as usize) - mem::size_of::<*mut Slab>();
    ((obj - base) / stride) as u32
}

#[inline]
unsafe fn read_u32_at(slab: *mut Slab, idx: u32) -> u32 {
    let sz = (*slab).obj_size as usize;
    let obj = obj_ptr(slab, idx as usize, sz);
    let next_slot = obj.add(mem::size_of::<*mut Slab>()) as *const u32;
    *next_slot
}

#[inline]
unsafe fn write_u32_at(slab: *mut Slab, idx: u32, val: u32) {
    let sz = (*slab).obj_size as usize;
    let obj = obj_ptr(slab, idx as usize, sz);
    let next_slot = obj.add(mem::size_of::<*mut Slab>()) as *mut u32;
    *next_slot = val;
}

unsafe fn unmap_slab_pages(slab: *mut Slab) {
    let pages = (*slab).pages as usize;
    let base = (*slab).base_va;
    unmap_large_pages(base, pages, false);
}

// Large path — VM backed, page-granular (+ optional guards)

unsafe fn kalloc_large(size: usize, align: usize, zero_on_alloc: bool) -> *mut u8 {
    let pages = ((size + PAGE_SIZE - 1) / PAGE_SIZE).max(1);
    let base = map_large_pages(pages, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL, HEAP.lock().pol.guard_large);
    if base.as_u64() == 0 { return core::ptr::null_mut(); }

    // Alignment > 4K would require overmap+trim; not supported yet.
    debug_assert!(align <= PAGE_SIZE);

    let ptr = base.as_u64() as *mut u8;
    if zero_on_alloc || matches!(HEAP.lock().pol.zero, ZeroPolicy::OnAlloc) {
        ptr::write_bytes(ptr, 0, pages * PAGE_SIZE);
    }

    HEAP.lock().alloc_large.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    ptr
}

unsafe fn kfree_large(p: *mut u8, size: usize) {
    let pages = ((size + PAGE_SIZE - 1) / PAGE_SIZE).max(1);
    unmap_large_pages(VirtAddr::new(p as u64), pages, HEAP.lock().pol.guard_large);
    HEAP.lock().free_large.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Map `pages` of anonymous kernel memory; if guard=true, keep 1 page gaps around.
pub unsafe fn map_large_pages(pages: usize, flags: VmFlags, guard: bool) -> VirtAddr {
    let h = HEAP.lock();
    let mut cursor = *h.vm_cursor.get();
    let heap_end = KHEAP_BASE + KHEAP_SIZE;

    // Align cursor to 4K
    cursor = (cursor + (PAGE_SIZE as u64 - 1)) & !((PAGE_SIZE as u64) - 1);

    let guard_pages = if guard { 1 } else { 0 };
    let total = pages + 2 * guard_pages;

    // Check window overflow
    if cursor + (total * PAGE_SIZE) as u64 > heap_end {
        return VirtAddr::zero();
    }

    // Map user-visible region starting after the left guard
    let start_va = VirtAddr::new(cursor + (guard_pages * PAGE_SIZE) as u64);

    for i in 0..pages {
        // Prefer lowmem frames if requested (helps some devices)
        let mut pflags = if h.pol.prefer_lowmem { PFlags::LOWMEM } else { PFlags::empty() };
        let f = phys::alloc(pflags).expect("OOM phys in map_large_pages");
        let va = VirtAddr::new(start_va.as_u64() + (i * PAGE_SIZE) as u64);
        virt::map4k_at(va, PhysAddr::new(f.0), flags).expect("map4k failed");
    }

    // Advance cursor beyond right guard if any
    *h.vm_cursor.get() = cursor + (total * PAGE_SIZE) as u64;

    start_va
}

unsafe fn unmap_large_pages(base: VirtAddr, pages: usize, guard: bool) {
    let _guard_pages = if guard { 1 } else { 0 };
    for i in (0..pages).rev() {
        let va = VirtAddr::new(base.as_u64() + (i * PAGE_SIZE) as u64);
        if let Ok((pa, _f, _s)) = virt::translate(va) {
            virt::unmap4k(va).expect("unmap4k");
            phys::free(Frame(pa.as_u64()));
        }
    }
}

// Convenience helpers

pub fn allocate_kernel_pages(pages: usize) -> Result<VirtAddr, &'static str> {
    let addr = unsafe { kalloc_pages(pages, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL) };
    if addr.as_u64() == 0 { Err("kalloc_pages failed") } else { Ok(addr) }
}

pub fn allocate_frame() -> Option<PhysAddr> { crate::memory::frame_alloc::allocate_frame() }
pub fn deallocate_frame(addr: PhysAddr) { crate::memory::frame_alloc::deallocate_frame(addr) }

pub unsafe fn kalloc(size: usize) -> *mut core::ffi::c_void {
    let layout = core::alloc::Layout::from_size_align(size, 8).unwrap();
    // Use the heap allocation system directly
    if size == 0 { return core::ptr::null_mut(); }
    kalloc_large(size, 8, false) as *mut core::ffi::c_void
}

pub unsafe fn kfree_void(ptr: *mut core::ffi::c_void) {
    if !ptr.is_null() {
        let layout = core::alloc::Layout::from_size_align(8, 8).unwrap();
        // Use the heap deallocation system directly  
        kfree_large(ptr as *mut u8, 8);
    }
}

/// Allocate kernel memory with real physical frame backing and virtual mapping
pub fn allocate_kernel_memory(size: usize) -> Result<VirtAddr, &'static str> {
    // Align size to page boundary for kernel allocations
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let pages = aligned_size / PAGE_SIZE;
    
    if pages == 0 {
        return Err("Zero-size allocation");
    }
    
    // Use existing large page allocator which handles physical mapping
    let virt_start = unsafe { map_large_pages(pages, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL, false) };
    
    if virt_start.as_u64() == 0 {
        return Err("Failed to allocate virtual memory");
    }
    
    // Zero the allocated memory for security
    unsafe {
        ptr::write_bytes(virt_start.as_mut_ptr::<u8>(), 0, aligned_size);
    }
    
    Ok(virt_start)
}

