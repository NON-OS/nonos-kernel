//! Kernel heap allocator (slab + VM) for NØNOS.
//!
//! Design
//!  - Small/medium sizes served from per-CPU magazines over page-backed slabs.
//!  - Large sizes served by VM: page-granular map/unmap (+ optional guard
//!    pages).
//!  - Zero-on-free by default (zero-state posture). Zero-on-alloc optional.
//!  - NUMA/zone hints forwarded to phys (DMA32/LOWMEM supported).
//!  - Proof posture: page map/unmap audited via virt hooks; phys frames
//!    audited.
//!
//! Not a global #[alloc_error_handler]; this is the kernel-internal heap API.
//! Exposes: kmalloc/kfree, kalloc_aligned, kalloc_pages/kfree_pages, stats().

#![allow(dead_code)]

use core::{cell::UnsafeCell, mem, ptr};
use spin::{Lazy, Mutex};
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::layout::{KHEAP_BASE, PAGE_SIZE};
use crate::memory::phys::{self, AllocFlags as PFlags, Frame};
use crate::memory::virt::{self, VmFlags};

/// Number of magazines per heap instance
const NUM_MAGS: usize = 8;

/// Heap allocation statistics
#[derive(Debug, Clone, Copy)]
struct HeapStats {
    alloced: usize,
    peak: usize,
    magazines_hit: usize,
    vm_allocs: usize,
}

/// Zero policy for small/large allocs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroPolicy {
    OnFree,
    OnAlloc,
    Never,
}

/// Heap policy (set at init).
#[derive(Clone, Copy, Debug)]
pub struct HeapPolicy {
    pub zero: ZeroPolicy,    // default: OnFree
    pub guard_large: bool,   // add 1 guard page before/after large-alloc mappings
    pub prefer_lowmem: bool, // prefer <=4GiB phys frames for slabs
}

impl Default for HeapPolicy {
    fn default() -> Self {
        Self { zero: ZeroPolicy::OnFree, guard_large: true, prefer_lowmem: true }
    }
}

/// Size classes (bytes). Keep power-of-two to simplify magazines.
const CLASSES: &[usize] = &[16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

/// Slab header precedes objects in the same mapped pages.
#[repr(C)]
struct Slab {
    class: u32,        // index into CLASSES
    obj_size: u32,     // bytes per object (class size)
    used: u32,         // in-use count
    cap: u32,          // capacity (#objects)
    free_head: u32,    // index of first free; 0xFFFF_FFFF = none
    next: *mut Slab,   // linked list in a magazine
    base_va: VirtAddr, // base VA of the slab's mapped pages
    pages: u32,        // #4K pages backing this slab
}

/// Per-CPU magazine: intrusive list of slabs for each class + a local bump.
struct Magazine {
    head: [*mut Slab; CLASSES_LEN],
}

unsafe impl Send for Magazine {}
unsafe impl Sync for Magazine {}

impl Heap {
    const fn new() -> Self {
        Self {
            pol: HeapPolicy { zero: ZeroPolicy::OnFree, guard_large: true, prefer_lowmem: false },
            mags: {
                const INIT: UnsafeCell<Magazine> = UnsafeCell::new(Magazine::new());
                [INIT; MAX_CPUS]
            },
            vm_cursor: UnsafeCell::new(KHEAP_BASE),
            alloc_small: core::sync::atomic::AtomicU64::new(0),
            free_small: core::sync::atomic::AtomicU64::new(0),
            alloc_large: core::sync::atomic::AtomicU64::new(0),
            free_large: core::sync::atomic::AtomicU64::new(0),
        }
    }
}

const CLASSES_LEN: usize = 13;

impl Magazine {
    const fn new() -> Self {
        Self { head: [core::ptr::null_mut(); CLASSES_LEN] }
    }
}

/// Global heap state.
struct Heap {
    pol: HeapPolicy,
    /// Per-CPU magazines. For now single-CPU bring-up uses slot 0 only.
    mags: [UnsafeCell<Magazine>; MAX_CPUS],
    /// Bump VA for large VM allocations.
    vm_cursor: UnsafeCell<u64>,
    /// Stats (best-effort).
    alloc_small: core::sync::atomic::AtomicU64,
    free_small: core::sync::atomic::AtomicU64,
    alloc_large: core::sync::atomic::AtomicU64,
    free_large: core::sync::atomic::AtomicU64,
}

unsafe impl Sync for Heap {} // UnsafeCell per-CPU is fine under our discipline.

const MAX_CPUS: usize = 64;

/// One global heap.
static HEAP: Lazy<Mutex<Heap>> = Lazy::new(|| {
    Mutex::new(Heap {
        pol: HeapPolicy::default(),
        mags: [const { UnsafeCell::new(Magazine::new()) }; MAX_CPUS],
        vm_cursor: UnsafeCell::new(0xFFFF_FFFF_C000_0000u64), // example high VA pool
        alloc_small: 0u64.into(),
        free_small: 0u64.into(),
        alloc_large: 0u64.into(),
        free_large: 0u64.into(),
    })
});

#[inline(always)]
fn cpu_id() -> usize {
    crate::arch::x86_64::cpu::current_cpu_id()
}

// ───────────────────────────────────────────────────────────────────────────────
// Public API
// ───────────────────────────────────────────────────────────────────────────────

pub fn init(policy: HeapPolicy) {
    let mut h = HEAP.lock();
    h.pol = policy;
}

/// Allocate `size` bytes, alignment = class size (<=64K). Returns ptr or null.
pub unsafe fn kmalloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    if let Some((class, sz)) = class_for(size) {
        alloc_small(class, sz)
    } else {
        // route to large VM path (page-granular)
        kalloc_large(size, 16, /* align hint */ true)
    }
}

/// Allocate `size` bytes aligned to `align` (power-of-two). Falls back to VM
/// path if >64K or alignment > class.
pub unsafe fn kalloc_aligned(size: usize, align: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    if align.is_power_of_two() && align <= 65536 {
        if let Some((class, sz)) = class_for(size.max(align)) {
            return alloc_small(class, sz);
        }
    }
    kalloc_large(size, align.max(16), true)
}

/// Free a pointer returned by kmalloc/kalloc_aligned.
pub unsafe fn kfree(p: *mut u8, size: usize) {
    if p.is_null() {
        return;
    }
    if let Some((class, sz)) = class_for(size) {
        free_small(p, class, sz);
    } else {
        kfree_large(p, size);
    }
}

/// Page-granular allocation (N pages). Optional guard pages from policy.
pub unsafe fn kalloc_pages(pages: usize, flags: VmFlags) -> VirtAddr {
    if pages == 0 {
        return VirtAddr::zero();
    }
    map_large_pages(pages, flags, /* guard= */ HEAP.lock().pol.guard_large)
}

/// Free page-granular allocation (must match pages used).
pub unsafe fn kfree_pages(base: VirtAddr, pages: usize) {
    if pages == 0 {
        return;
    }
    unmap_large_pages(base, pages, /* guard= */ HEAP.lock().pol.guard_large)
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

// ───────────────────────────────────────────────────────────────────────────────
// Small/medium path — magazines + slabs
// ───────────────────────────────────────────────────────────────────────────────

#[inline]
fn class_for(n: usize) -> Option<(usize, usize)> {
    for (i, &c) in CLASSES.iter().enumerate() {
        if c >= n {
            return Some((i, c));
        }
    }
    None
}

unsafe fn alloc_small(class: usize, sz: usize) -> *mut u8 {
    let h = HEAP.lock();
    let cpu = cpu_id();
    let mag = &mut *h.mags[cpu].get();

    // try fast path: use head slab
    let head = mag.head[class];
    if !head.is_null() {
        if let Some(p) = carve_obj_from_slab(head, &h.pol) {
            h.alloc_small.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            return p;
        }
    }

    // need a new slab: allocate page(s), map, format freelist
    let slab = new_slab(class, sz, &h.pol);
    if slab.is_null() {
        return core::ptr::null_mut();
    }
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

    // locate slab header: lives at base_va (first page): we stash a back-pointer
    // Layout: [Slab hdr | free list | objects...]; hdr at base_va.
    // For simplicity, store the slab hdr pointer just before each object (8B).
    let slab_ptr = *((p as usize - mem::size_of::<*mut Slab>()) as *const *mut Slab);
    let slab = slab_ptr;

    // zero policy
    if matches!(h.pol.zero, ZeroPolicy::OnFree) {
        ptr::write_bytes(p, 0, sz);
    }

    // push back into freelist
    let idx = obj_index_in_slab(slab, p, sz);
    let head = (*slab).free_head;
    write_u32_at(slab, idx, head); // store next idx at object prefix
    (*slab).free_head = idx;
    (*slab).used -= 1;

    // if slab empty and not the head, we can reclaim pages (optional policy)
    if (*slab).used == 0 {
        // unlink from magazine list
        let mut prev: *mut Slab = core::ptr::null_mut();
        let mut cur = mag.head[class];
        while !cur.is_null() {
            if cur == slab {
                if prev.is_null() {
                    mag.head[class] = (*cur).next;
                } else {
                    (*prev).next = (*cur).next;
                }
                break;
            }
            prev = cur;
            cur = (*cur).next;
        }
        // unmap pages backing this slab
        unmap_slab_pages(slab);
    }

    h.free_small.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Allocate and format a new slab for class `class` size `sz`.
unsafe fn new_slab(class: usize, sz: usize, _pol: &HeapPolicy) -> *mut Slab {
    // Choose pages: try to fit reasonable number of objects. Target ~4–8 KiB object
    // space.
    let mut pages = 1usize;
    while pages * PAGE_SIZE < (sz * 32 + mem::size_of::<Slab>() + 256) {
        pages *= 2;
        if pages >= 16 {
            break;
        } // cap slab at 64 KiB
    }
    // Map pages for the slab
    let va = map_large_pages(pages, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL, false);
    if va.is_null() {
        return core::ptr::null_mut();
    }

    // Layout: [Slab hdr][(obj_count * 4B) freelist array][objs each with 8B backptr
    // prefix]
    let hdr = va.as_u64() as *mut Slab;
    ptr::write_bytes(hdr as *mut u8, 0, mem::size_of::<Slab>());

    let slab_bytes = pages * PAGE_SIZE;
    let meta_off = mem::size_of::<Slab>();
    let area = slab_bytes - meta_off;
    // Each object stored as: [*mut Slab backptr (8B)] [payload (sz bytes)]
    let stride = mem::size_of::<*mut Slab>() + sz;
    let cap = area / stride;

    (*hdr).class = class as u32;
    (*hdr).obj_size = sz as u32;
    (*hdr).used = 0;
    (*hdr).cap = cap as u32;
    (*hdr).free_head = 0; // 0..cap-1; use 0-based list
    (*hdr).next = core::ptr::null_mut();
    (*hdr).base_va = VirtAddr::new(va.as_u64());
    (*hdr).pages = pages as u32;

    // Build freelist: obj i's first 8B store slab backptr, next 4B store next index
    for i in 0..cap {
        let obj = obj_ptr(hdr, i, sz);
        // back-pointer to slab
        *(obj as *mut *mut Slab) = hdr;
        // next index (u32) placed right after backptr
        let next = if i + 1 < cap { (i + 1) as u32 } else { 0xFFFF_FFFF };
        let next_slot = obj.add(mem::size_of::<*mut Slab>()) as *mut u32;
        *next_slot = next;
    }

    hdr
}

#[inline]
unsafe fn carve_obj_from_slab(slab: *mut Slab, pol: &HeapPolicy) -> Option<*mut u8> {
    let head = (*slab).free_head;
    if head == 0xFFFF_FFFF {
        return None;
    }
    let sz = (*slab).obj_size as usize;
    let obj = obj_ptr(slab, head as usize, sz);
    // advance head to "next" index
    (*slab).free_head = read_u32_at(slab, head);
    (*slab).used += 1;

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
    // Unmap slab->pages pages and free their frames.
    let pages = (*slab).pages as usize;
    let base = (*slab).base_va;
    unmap_large_pages(base, pages, false);
}

// ───────────────────────────────────────────────────────────────────────────────
// Large path — VM backed, page-granular (+ optional guards)
// ───────────────────────────────────────────────────────────────────────────────

unsafe fn kalloc_large(size: usize, align: usize, zero_on_alloc: bool) -> *mut u8 {
    // Round up to pages
    let pages = ((size + PAGE_SIZE - 1) / PAGE_SIZE).max(1);
    let base = map_large_pages(
        pages,
        VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL,
        HEAP.lock().pol.guard_large,
    );
    if base.is_null() {
        return core::ptr::null_mut();
    }

    // Alignment: if caller asked for > 4K, we can over-map and return aligned
    // subrange. For now keep it simple: require align <= 4K for large path.
    // (Extend later: overmap+trim)
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
    // We assume kalloc_large mapped exactly `pages` (plus guards managed by helper)
    unmap_large_pages(VirtAddr::new(p as u64), pages, HEAP.lock().pol.guard_large);
    HEAP.lock().free_large.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Map `pages` of anonymous kernel memory; if guard=true add one guard page
/// before & after.
unsafe fn map_large_pages(pages: usize, flags: VmFlags, guard: bool) -> VirtAddr {
    let h = HEAP.lock();
    let mut cursor = *h.vm_cursor.get();
    // align cursor to page
    cursor = (cursor + (PAGE_SIZE as u64 - 1)) & !((PAGE_SIZE as u64) - 1);

    let guard_pages = if guard { 1 } else { 0 };
    let total = pages + 2 * guard_pages;

    // Map pages with fresh frames
    let start_va = VirtAddr::new(cursor + (guard_pages * PAGE_SIZE) as u64);
    for i in 0..pages {
        // pick zone prefs
        let mut pflags = if h.pol.prefer_lowmem { PFlags::LOWMEM } else { PFlags::empty() };
        // allocate one frame
        let f = phys::alloc(pflags).expect("OOM phys in map_large_pages");
        // map VA -> PA
        let va = VirtAddr::new(start_va.as_u64() + (i * PAGE_SIZE) as u64);
        virt::map4k_at(va, PhysAddr::new(f.0), flags).expect("map4k failed");
        // phys allocation already audited by phys; map audited by virt
    }
    // Move cursor
    *h.vm_cursor.get() = cursor + (total * PAGE_SIZE) as u64;

    start_va
}

unsafe fn unmap_large_pages(base: VirtAddr, pages: usize, guard: bool) {
    let _guard_pages = if guard { 1 } else { 0 };
    // Unmap in reverse to reduce transient overlap (cosmetic)
    for i in (0..pages).rev() {
        let va = VirtAddr::new(base.as_u64() + (i * PAGE_SIZE) as u64);
        // translate to get PA to free frame
        if let Ok((pa, _f, _sz)) = virt::translate(va) {
            virt::unmap4k(va).expect("unmap4k");
            phys::free(Frame(pa.as_u64()));
        }
    }
    // (guard pages are unmapped implicitly as we never mapped them)
}

/// Helper function for advanced memory management
pub fn allocate_kernel_memory(size: usize) -> Result<VirtAddr, &'static str> {
    let ptr = unsafe { kmalloc(size) };
    if ptr.is_null() {
        Err("Failed to allocate kernel memory")
    } else {
        Ok(VirtAddr::new(ptr as usize as u64))
    }
}

/// Helper function for allocating kernel pages
pub fn allocate_kernel_pages(pages: usize) -> Result<VirtAddr, &'static str> {
    let addr = unsafe {
        kalloc_pages(
            pages,
            crate::memory::virt::VmFlags::RW
                | crate::memory::virt::VmFlags::NX
                | crate::memory::virt::VmFlags::GLOBAL,
        )
    };
    if addr.is_null() {
        Err("Failed to allocate kernel pages")
    } else {
        Ok(addr)
    }
}

/// Allocate a physical frame
pub fn allocate_frame() -> Option<PhysAddr> {
    crate::memory::frame_alloc::allocate_frame()
}

/// Deallocate a physical frame  
pub fn deallocate_frame(addr: PhysAddr) {
    crate::memory::frame_alloc::deallocate_frame(addr)
}

// ───────────────────────────────────────────────────────────────────────────────
// Notes
//  - Magazine is per-CPU but we haven't implemented stealing/cross-CPU yet.
//  - Double-free defense is minimal (slab backptr + index math).
//  - For real SMP, add a small quarantine ring per class to catch ABA.
//  - Overaligned large allocations could overmap+trim (TODO).
//  - Fragmentation: slab empty reclaim does page unmap immediately.
// ───────────────────────────────────────────────────────────────────────────────
