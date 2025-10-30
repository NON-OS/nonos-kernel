#![no_std]

use core::ops::Range;
use core::cmp;
use core::convert::TryInto;

use crate::memory::nonos_kaslr;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_MASK: u64 = !(PAGE_SIZE as u64 - 1);
pub const HUGE_2M: usize = 2 * 1024 * 1024;
pub const HUGE_1G: usize = 1024 * 1024 * 1024;

pub const CANON_LOW_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;
pub const CANON_HIGH_MIN: u64 = 0xFFFF_8000_0000_0000;

pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;
pub const USER_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_TOP: u64 = CANON_LOW_MAX;

pub const KPTI_TRAMPOLINE: u64 = 0xFFFF_FFFF_FFFE_0000;

pub const PCID_KERNEL: u16 = 0x0001;
pub const PCID_USER: u16 = 0x0002;

pub const SELFREF_SLOT: usize = 510;

#[inline(always)]
pub const fn selfref_l4_va() -> u64 {
    let i = SELFREF_SLOT as u64;
    (0xFFFFu64 << 48) | (i << 39) | (i << 30) | (i << 21) | (i << 12)
}

pub const KTEXT_BASE: u64 = KERNEL_BASE;
pub const KDATA_BASE: u64 = KERNEL_BASE + 0x0000_0200_0000;

pub const DIRECTMAP_BASE: u64 = 0xFFFF_FFFF_B000_0000;
pub const DIRECTMAP_SIZE: u64 = 0x0000_0000_1000_0000;

pub const KHEAP_BASE: u64 = 0xFFFF_FF00_0000_0000;
pub const KHEAP_SIZE: u64 = 0x0000_0000_1000_0000;

pub const KVM_BASE: u64 = 0xFFFF_FF10_0000_0000;
pub const KVM_SIZE: u64 = 0x0000_0000_2000_0000;

pub const MMIO_BASE: u64 = 0xFFFF_FF30_0000_0000;
pub const MMIO_SIZE: u64 = 0x0000_0000_2000_0000;

pub const VMAP_BASE: u64 = 0xFFFF_FF50_0000_0000;
pub const VMAP_SIZE: u64 = 0x0000_0000_1000_0000;

pub const MAX_PHYS_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;

pub const DMA_BASE: u64 = 0xFFFF_FF60_0000_0000;
pub const DMA_SIZE: u64 = 0x0000_0000_1000_0000;

pub const FIXMAP_BASE: u64 = 0xFFFF_FFA0_0000_0000;
pub const FIXMAP_SIZE: u64 = 0x0000_0010_0000_0000;

pub const BOOT_IDMAP_BASE: u64 = 0xFFFF_FFB0_0000_0000;
pub const BOOT_IDMAP_SIZE: u64 = 0x0000_1000_0000;

pub const PERCPU_BASE: u64 = 0xFFFF_FFC0_0000_0000;
pub const PERCPU_STRIDE: u64 = 0x0000_0100_0000;

pub const KSTACK_SIZE: usize = 64 * 1024;
pub const IST_STACK_SIZE: usize = 32 * 1024;
pub const GUARD_PAGES: usize = 1;

#[inline(always)]
pub const fn align_down(x: u64, a: u64) -> u64 { 
    if a == 0 || (a & (a - 1)) != 0 { 
        return x; // Invalid alignment, return as-is
    }
    x & !(a - 1) 
}

#[inline(always)]
pub const fn align_up(x: u64, a: u64) -> u64 { 
    if a == 0 || (a & (a - 1)) != 0 { 
        return x; // Invalid alignment, return as-is
    }
    (x + a - 1) & !(a - 1) 
}

#[inline(always)]
pub const fn is_aligned(x: u64, a: u64) -> bool { 
    if a == 0 { return false; }
    (x & (a - 1)) == 0 
}

#[inline(always)]
pub const fn in_kernel_space(va: u64) -> bool { va >= CANON_HIGH_MIN }

#[inline(always)]
pub const fn in_user_space(va: u64) -> bool { va <= USER_TOP }

#[inline(always)]
pub const fn range(base: u64, size: u64) -> Range<u64> { base..(base.saturating_add(size)) }

#[derive(Clone, Copy, Debug)]
pub struct Section { pub start: u64, pub end: u64, pub rx: bool, pub rw: bool, pub nx: bool, pub global: bool }
impl Section { pub const fn size(&self) -> u64 { self.end - self.start } }

extern "C" {
    // Symbols in kernel linker script.
    static __kernel_start: u8;
    static __kernel_text_start: u8;
    static __kernel_text_end: u8;
    static __kernel_rodata_start: u8;
    static __kernel_rodata_end: u8;
    static __kernel_data_start: u8;
    static __kernel_data_end: u8;
    static __kernel_bss_start: u8;
    static __kernel_bss_end: u8;
    static __kernel_end: u8;

    static __boot_stacks_start: u8;
    static __boot_stacks_end: u8;

    static __percpu_start: u8;
    static __percpu_end: u8;
}

pub fn kernel_sections() -> [Section; 4] {
    unsafe {
        [
            Section { start: &__kernel_text_start as *const _ as u64, end: &__kernel_text_end as *const _ as u64, rx: true,  rw: false, nx: false, global: true },
            Section { start: &__kernel_rodata_start as *const _ as u64, end: &__kernel_rodata_end as *const _ as u64, rx: false, rw: false, nx: true,  global: true },
            Section { start: &__kernel_data_start as *const _ as u64, end: &__kernel_data_end as *const _ as u64, rx: false, rw: true,  nx: true,  global: true },
            Section { start: &__kernel_bss_start  as *const _ as u64, end: &__kernel_bss_end   as *const _ as u64, rx: false, rw: true,  nx: true,  global: true },
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind { Available, Usable, Reserved, Acpi, Mmio, Kernel, Boot, Unknown }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region { pub start: u64, pub end: u64, pub kind: RegionKind }

impl Region { 
    pub const fn len(&self) -> u64 { self.end - self.start } 
    pub const fn is_usable(&self) -> bool { matches!(self.kind, RegionKind::Usable | RegionKind::Available) }
    pub const fn start_addr(&self) -> u64 { self.start }
    pub const fn end_addr(&self) -> u64 { self.end }
}

pub fn region_from_firmware(kind_code: u32, start: u64, len: u64) -> Region {
    let kind = match kind_code { 1 => RegionKind::Usable, 2 => RegionKind::Reserved, 3 | 4 => RegionKind::Acpi, 7 => RegionKind::Mmio, _ => RegionKind::Unknown };
    Region { start, end: start + len, kind }
}

pub fn managed_span(rs: &[Region]) -> (u64, u64) {
    let mut lo = u64::MAX; let mut hi = 0u64;
    for r in rs { if r.is_usable() { let s = align_up(r.start, PAGE_SIZE as u64); let e = align_down(r.end, PAGE_SIZE as u64); if e > s { lo = lo.min(s); hi = hi.max(e); } } }
    if lo > hi { (0,0) } else { (lo, hi) }
}

#[derive(Clone, Copy, Debug)]
pub struct LayoutConfig { pub slide: u64, pub heap_lo: u64, pub heap_sz: u64, pub vm_lo:   u64, pub vm_sz:   u64, pub mmio_lo: u64, pub mmio_sz: u64 }
impl Default for LayoutConfig { fn default() -> Self { Self { slide: 0, heap_lo: KHEAP_BASE, heap_sz: KHEAP_SIZE, vm_lo: KVM_BASE, vm_sz: KVM_SIZE, mmio_lo: MMIO_BASE, mmio_sz: MMIO_SIZE } } }

pub static mut LAYOUT: LayoutConfig = LayoutConfig { slide: 0, heap_lo: KHEAP_BASE, heap_sz: KHEAP_SIZE, vm_lo: KVM_BASE, vm_sz: KVM_SIZE, mmio_lo: MMIO_BASE, mmio_sz: MMIO_SIZE };

pub fn apply_kaslr_slide(slide: u64) -> Result<(), &'static str> {
    if slide & (PAGE_SIZE as u64 - 1) != 0 { return Err("slide not page-aligned"); }
    unsafe {
        LAYOUT.slide = slide;
        // update derived windows
        LAYOUT.heap_lo = KHEAP_BASE.wrapping_add(slide);
        LAYOUT.vm_lo   = KVM_BASE.wrapping_add(slide);
        LAYOUT.mmio_lo = MMIO_BASE.wrapping_add(slide);
    }
    Ok(())
}

pub fn slid_address(base: u64) -> u64 {
    unsafe { base.wrapping_add(LAYOUT.slide) }
}

pub fn slid_range(base: u64, size: u64) -> Range<u64> {
    let b = slid_address(base);
    b..b.saturating_add(size)
}

pub fn validate_layout() -> Result<(), &'static str> {
    // basic invariants
    if KERNEL_BASE < CANON_HIGH_MIN { return Err("kernel base below higher-half"); }
    if PERCPU_STRIDE % (PAGE_SIZE as u64) != 0 { return Err("percpu stride misaligned"); }

    let pairs: &[(u64,u64,u64,u64)] = &[
        (KTEXT_BASE, 0x0200_0000, KDATA_BASE, 0x0200_0000),
        (KDATA_BASE, 0x0200_0000, DIRECTMAP_BASE, DIRECTMAP_SIZE),
        (DIRECTMAP_BASE, DIRECTMAP_SIZE, KHEAP_BASE, KHEAP_SIZE),
        (KHEAP_BASE, KHEAP_SIZE, KVM_BASE, KVM_SIZE),
        (KVM_BASE, KVM_SIZE, MMIO_BASE, MMIO_SIZE),
        (MMIO_BASE, MMIO_SIZE, VMAP_BASE, VMAP_SIZE),
    ];

    unsafe {
        let slide = LAYOUT.slide;
        for &(a0, asz, b0, bsz) in pairs {
            let a0s = a0.wrapping_add(slide);
            let b0s = b0.wrapping_add(slide);
            if a0s < b0s + bsz && b0s < a0s + asz { return Err("layout window overlap"); }
            if a0s > b0s { return Err("layout order violation"); }
        }
    }

    Ok(())
}

pub fn kernel_vaddr_to_phys(v: u64) -> Option<u64> {
    if !in_kernel_space(v) { return None; }
    let slide = unsafe { LAYOUT.slide };
    Some(v.wrapping_sub(slide).wrapping_sub(KERNEL_BASE - 0))
}

pub fn heap_base_for(size: usize) -> Result<u64, &'static str> {
    let slide = unsafe { LAYOUT.slide };
    let base = KHEAP_BASE.wrapping_add(slide);
    let aligned = align_up(base, PAGE_SIZE as u64);
    if size as u64 > unsafe { LAYOUT.heap_sz } { return Err("request > heap size"); }
    Ok(aligned)
}

pub fn vm_window() -> (u64, u64) {
    let slide = unsafe { LAYOUT.slide };
    (KVM_BASE.wrapping_add(slide), KVM_SIZE)
}

pub fn log_kernel_sections(mut log: impl FnMut(&str)) {
    for s in kernel_sections().iter() {
        let perm = if s.rx { "RX" } else if s.rw { "RW" } else { "R" };
        let nx   = if s.nx { "NX" } else { "X" };
        log(&alloc::format!("[layout] {:#016x}-{:#016x} {:>6}KiB {} {} global={}", slid_address(s.start), slid_address(s.end), s.size()/1024, perm, nx, s.global));
    }
}

pub fn randomize_layout_from_kaslr(policy: crate::memory::nonos_kaslr::Policy) -> Result<nonos_kaslr::Kaslr, &'static str> {
    match nonos_kaslr::init(policy) {
        Ok(k) => {
            apply_kaslr_slide(k.slide)?;
            Ok(k)
        }
        Err(e) => Err(e)
    }
}

#[derive(Debug, Clone)]
pub struct StackRegion {
    pub base: u64,
    pub size: usize,
    pub guard_size: usize,
    pub cpu_id: Option<u32>,
    pub thread_id: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PercpuRegion {
    pub base: u64,
    pub size: usize,
    pub cpu_id: u32,
}

#[derive(Debug, Clone)]
pub struct ModuleRegion {
    pub base: u64,
    pub size: usize,
    pub name: &'static str,
    pub permissions: u32,
}

pub fn get_all_stack_regions() -> alloc::vec::Vec<StackRegion> {
    let mut regions = alloc::vec::Vec::new();
    
    // Add main kernel stacks
    let max_cpus = 64; // Reasonable default
    for cpu_id in 0..max_cpus {
        let stack_base = PERCPU_BASE + (cpu_id as u64) * PERCPU_STRIDE;
        regions.push(StackRegion {
            base: stack_base,
            size: KSTACK_SIZE,
            guard_size: GUARD_PAGES * PAGE_SIZE,
            cpu_id: Some(cpu_id),
            thread_id: None,
        });
        
        // IST stacks
        for ist_num in 0..8 {
            regions.push(StackRegion {
                base: stack_base + KSTACK_SIZE as u64 + (ist_num * IST_STACK_SIZE) as u64,
                size: IST_STACK_SIZE,
                guard_size: GUARD_PAGES * PAGE_SIZE,
                cpu_id: Some(cpu_id),
                thread_id: None,
            });
        }
    }
    
    regions
}

pub fn get_percpu_regions() -> alloc::vec::Vec<PercpuRegion> {
    let mut regions = alloc::vec::Vec::new();
    let max_cpus = 64;
    
    for cpu_id in 0..max_cpus {
        regions.push(PercpuRegion {
            base: PERCPU_BASE + (cpu_id as u64) * PERCPU_STRIDE,
            size: PERCPU_STRIDE as usize,
            cpu_id,
        });
    }
    
    regions
}

pub fn get_module_regions() -> alloc::vec::Vec<ModuleRegion> {
    let mut regions = alloc::vec::Vec::new();
    
    // Add kernel sections as module regions
    for section in kernel_sections().iter() {
        let mut perms = 0;
        if section.rx { perms |= 1; }
        if section.rw { perms |= 2; }
        if !section.nx { perms |= 4; }
        
        regions.push(ModuleRegion {
            base: section.start,
            size: section.size() as usize,
            name: "kernel",
            permissions: perms,
        });
    }
    
    regions
}