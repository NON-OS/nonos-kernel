// NØNOS memory layout (x86_64, 4-level, higher-half, W^X).

#![allow(dead_code)]

use core::ops::Range;
use alloc::format;

// Page sizes, masks, canonical

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_MASK: u64   = !(PAGE_SIZE as u64 - 1);
pub const HUGE_2M:   usize = 2 * 1024 * 1024;
pub const HUGE_1G:   usize = 1024 * 1024 * 1024;

pub const CANON_LOW_MAX:  u64 = 0x0000_7FFF_FFFF_FFFF;
pub const CANON_HIGH_MIN: u64 = 0xFFFF_8000_0000_0000;

// Kernel/User split, KPTI trampoline, PCID domains

pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;
pub const USER_BASE:   u64 = 0x0000_0000_0000_0000;
pub const USER_TOP:    u64 = CANON_LOW_MAX;

pub const KPTI_TRAMPOLINE: u64 = 0xFFFF_FFFF_FFFE_0000;

pub const PCID_KERNEL: u16 = 0x0001;
pub const PCID_USER:   u16 = 0x0002;

// Self-referenced PML4 slot

pub const SELFREF_SLOT: usize = 510;

#[inline(always)]
pub const fn selfref_l4_va() -> u64 {
    let i = SELFREF_SLOT as u64;
    (0xFFFFu64 << 48) | (i << 39) | (i << 30) | (i << 21) | (i << 12)
}

// Core virtual windows

pub const KTEXT_BASE: u64 = KERNEL_BASE;                    // .text/.rodata (RX,GLOBAL)
pub const KDATA_BASE: u64 = KERNEL_BASE + 0x0000_0200_0000; // .data/.bss/percpu (RW,NX,GLOBAL)

pub const DIRECTMAP_BASE: u64 = 0xFFFF_FFFF_B000_0000; // phys→virt linear window
pub const DIRECTMAP_SIZE: u64 = 0x0000_0000_1000_0000;

pub const KHEAP_BASE:  u64 = 0xFFFF_FF00_0000_0000; // kernel heap arena (VA only)
pub const KHEAP_SIZE:  u64 = 0x0000_0000_1000_0000;

pub const KVM_BASE:    u64 = 0xFFFF_FF10_0000_0000; // anon VM (kalloc_pages)
pub const KVM_SIZE:    u64 = 0x0000_0000_2000_0000;

pub const MMIO_BASE:   u64 = 0xFFFF_FF30_0000_0000; // device MMIO VA window
pub const MMIO_SIZE:   u64 = 0x0000_0000_2000_0000;

pub const VMAP_BASE:   u64 = 0xFFFF_FF50_0000_0000; // vmap/ioremap overflow
pub const VMAP_SIZE:   u64 = 0x0000_0000_1000_0000;

// Fixmap: small, fixed VA slots

pub const FIXMAP_BASE: u64 = 0xFFFF_FFA0_0000_0000;
pub const FIXMAP_SIZE: u64 = 0x0000_0010_0000_0000;

// Boot identity window

pub const BOOT_IDMAP_BASE: u64 = 0xFFFF_FFB0_0000_0000;
pub const BOOT_IDMAP_SIZE: u64 = 0x0000_1000_0000;

// Per-CPU TLS/GDT/TSS/stacks

pub const PERCPU_BASE:   u64 = 0xFFFF_FFC0_0000_0000;
pub const PERCPU_STRIDE: u64 = 0x0000_0100_0000;

// Stacks, IST, guards

pub const KSTACK_SIZE:    usize = 64 * 1024;
pub const IST_STACK_SIZE: usize = 32 * 1024;
pub const GUARD_PAGES:    usize = 1;

#[inline(always)]
pub const fn stack_guard_and_base(stack_top: u64) -> (u64, u64) {
    let guard = align_down(stack_top - (GUARD_PAGES as u64) * PAGE_SIZE as u64, PAGE_SIZE as u64);
    (guard, stack_top)
}

// PAT cache kinds

pub mod pat {
    pub const UC:       u8 = 0;
    pub const WC:       u8 = 1;
    pub const WT:       u8 = 4;
    pub const WP:       u8 = 5;
    pub const WB:       u8 = 6;
    pub const UcMinus: u8 = 7;
}

// Linker-provided section bounds (virt addresses)

extern "C" {
    pub static __kernel_start:        u8;
    pub static __kernel_text_start:   u8;
    pub static __kernel_text_end:     u8;
    pub static __kernel_rodata_start: u8;
    pub static __kernel_rodata_end:   u8;
    pub static __kernel_data_start:   u8;
    pub static __kernel_data_end:     u8;
    pub static __kernel_bss_start:    u8;
    pub static __kernel_bss_end:      u8;
    pub static __kernel_end:          u8;

    pub static __boot_stacks_start: u8;
    pub static __boot_stacks_end:   u8;

    pub static __percpu_start: u8;
    pub static __percpu_end:   u8;
}

#[derive(Clone, Copy, Debug)]
pub struct Section { pub start: u64, pub end: u64, pub rx: bool, pub rw: bool, pub nx: bool, pub global: bool }
impl Section { pub const fn size(&self) -> u64 { self.end - self.start } }

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

// NUMA-aware direct map stripes

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeStripe { pub node_id: u8, pub phys_lo: u64, pub phys_hi: u64, pub virt_lo: u64 }

pub const MAX_NODES: usize = 8;
pub static mut DIRECTMAP_STRIPES: [Option<NodeStripe>; MAX_NODES] = [None; MAX_NODES];

#[inline(always)]
pub fn directmap_va(paddr: u64) -> Option<u64> {
    unsafe {
        for s in DIRECTMAP_STRIPES.iter().flatten() {
            if paddr >= s.phys_lo && paddr < s.phys_hi {
                return Some(s.virt_lo + (paddr - s.phys_lo));
            }
        }
    }
    if paddr < DIRECTMAP_SIZE { Some(DIRECTMAP_BASE + paddr) } else { None }
}

// Firmware map glue (E820/UEFI → Region/Kind)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind { Available, Usable, Reserved, Acpi, Mmio, Kernel, Boot, Unknown }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub kind: RegionKind,
}

impl Region {
    pub const fn len(&self) -> u64 { self.end - self.start }
    pub const fn is_usable(&self) -> bool { matches!(self.kind, RegionKind::Usable | RegionKind::Available) }
}

pub fn region_from_firmware(kind_code: u32, start: u64, len: u64) -> Region {
    let kind = match kind_code {
        1 => RegionKind::Usable,
        2 => RegionKind::Reserved,
        3 | 4 => RegionKind::Acpi,
        7 => RegionKind::Mmio,
        _ => RegionKind::Unknown,
    };
    Region { start, end: start + len, kind }
}

pub fn managed_span(rs: &[Region]) -> (u64, u64) {
    let mut lo = u64::MAX; let mut hi = 0u64;
    for r in rs {
        if r.is_usable() {
            let s = align_up(r.start, PAGE_SIZE as u64);
            let e = align_down(r.end, PAGE_SIZE as u64);
            if e > s { lo = lo.min(s); hi = hi.max(e); }
        }
    }
    if lo > hi { (0, 0) } else { (lo, hi) }
}

// Alignment & range helpers

#[inline(always)] pub const fn align_down(x: u64, a: u64) -> u64 { x & !(a - 1) }
#[inline(always)] pub const fn align_up  (x: u64, a: u64) -> u64 { (x + a - 1) & !(a - 1) }
#[inline(always)] pub const fn is_aligned(x: u64, a: u64) -> bool { (x & (a - 1)) == 0 }

#[inline(always)] pub const fn in_kernel_space(va: u64) -> bool { va >= CANON_HIGH_MIN }
#[inline(always)] pub const fn range(base: u64, size: u64) -> Range<u64> { base..(base + size) }

// Runtime layout config (KASLR slide, dynamic window trims)

#[derive(Clone, Copy, Debug)]
pub struct LayoutConfig {
    pub slide: u64,
    pub heap_lo: u64,
    pub heap_sz: u64,
    pub vm_lo:   u64,
    pub vm_sz:   u64,
    pub mmio_lo: u64,
    pub mmio_sz: u64,
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            slide: 0,
            heap_lo: KHEAP_BASE, heap_sz: KHEAP_SIZE,
            vm_lo:   KVM_BASE,   vm_sz:   KVM_SIZE,
            mmio_lo: MMIO_BASE,  mmio_sz: MMIO_SIZE,
        }
    }
}

pub static mut LAYOUT: LayoutConfig = LayoutConfig {
    slide: 0,
    heap_lo: KHEAP_BASE, heap_sz: KHEAP_SIZE,
    vm_lo:   KVM_BASE,   vm_sz:   KVM_SIZE,
    mmio_lo: MMIO_BASE,  mmio_sz: MMIO_SIZE,
};

// Diagnostics

pub fn dump<F>(mut writer: F)
where
    F: FnMut(&str),
{
    unsafe {
        writer(&format!("Memory Layout:\n"));
        writer(&format!("  Kernel Base: 0x{:016x}\n", KERNEL_BASE));
        writer(&format!("  Heap Base:   0x{:016x} (size: 0x{:x})\n", LAYOUT.heap_lo, LAYOUT.heap_sz));
        writer(&format!("  VM Base:     0x{:016x} (size: 0x{:x})\n", LAYOUT.vm_lo, LAYOUT.vm_sz));
        writer(&format!("  MMIO Base:   0x{:016x} (size: 0x{:x})\n", LAYOUT.mmio_lo, LAYOUT.mmio_sz));
        writer(&format!("  KASLR Slide: 0x{:016x}\n", LAYOUT.slide));
    }
}

#[inline(always)] pub fn apply_slide(va: u64, slide: u64) -> u64 { va.wrapping_add(slide) }
#[inline(always)] pub fn remove_slide(va: u64, slide: u64) -> u64 { va.wrapping_sub(slide) }

// Fixmap slots

#[repr(usize)]
#[derive(Clone, Copy, Debug)]
pub enum FixmapSlot {
    EarlyConsole = 0,
    AcpiTable    = 1,
    TempPte      = 2,
    TempPde      = 3,
    TempStack    = 4,
}

#[inline(always)]
pub const fn fixmap_va(slot: FixmapSlot) -> u64 {
    FIXMAP_BASE + (slot as u64) * (PAGE_SIZE as u64)
}

// Runtime validation (non-fatal): ensures windows are ordered and non-overlapping.

#[inline(always)]
const fn non_overlapping(a_base: u64, a_size: u64, b_base: u64, b_size: u64) -> bool {
    let a_end = a_base.wrapping_add(a_size);
    let b_end = b_base.wrapping_add(b_size);
    !(a_base < b_end && b_base < a_end)
}

pub fn validate_layout() -> Result<(), &'static str> {
    // Higher-half invariant
    if KERNEL_BASE < CANON_HIGH_MIN { return Err("kernel base below higher-half"); }
    // Coarse ordering and non-overlap (using declared windows)
    let pairs: &[(u64,u64,u64,u64)] = &[
        (KTEXT_BASE, 0x0200_0000, KDATA_BASE, 0x0200_0000),       // 32 MiB text/rodata vs data/bss window
        (KDATA_BASE, 0x0200_0000, DIRECTMAP_BASE, DIRECTMAP_SIZE),
        (DIRECTMAP_BASE, DIRECTMAP_SIZE, KHEAP_BASE, KHEAP_SIZE),
        (KHEAP_BASE, KHEAP_SIZE, KVM_BASE, KVM_SIZE),
        (KVM_BASE, KVM_SIZE, MMIO_BASE, MMIO_SIZE),
        (MMIO_BASE, MMIO_SIZE, VMAP_BASE, VMAP_SIZE),
    ];
    for &(a0, asz, b0, bsz) in pairs {
        if !non_overlapping(a0, asz, b0, bsz) { return Err("layout window overlap"); }
        if a0 > b0 { return Err("layout order violation"); }
    }
    if PERCPU_STRIDE % (PAGE_SIZE as u64) != 0 { return Err("percpu stride misaligned"); }
    Ok(())
}

// Section logging

pub fn log_kernel_sections(log: &mut dyn FnMut(&str)) {
    for s in kernel_sections().iter() {
        let perm = if s.rx { "RX" } else if s.rw { "RW" } else { "R" };
        let nx   = if s.nx { "NX" } else { "X" };
        log(&format!(
            "[layout] {:#016x}-{:#016x} {:>6}KiB {} {} global={}",
            s.start, s.end, s.size()/1024, perm, nx, s.global
        ));
    }
}
