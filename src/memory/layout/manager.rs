// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::ops::Range;
use spin::RwLock;
use alloc::vec::Vec;
use crate::memory::kaslr;
use super::constants::*;
use super::error::{LayoutError, LayoutResult};
use super::types::*;
static LAYOUT: RwLock<LayoutConfig> = RwLock::new(LayoutConfig {
    slide: 0,
    heap_lo: KHEAP_BASE,
    heap_sz: KHEAP_SIZE,
    vm_lo: KVM_BASE,
    vm_sz: KVM_SIZE,
    mmio_lo: MMIO_BASE,
    mmio_sz: MMIO_SIZE,
    initialized: false,
});

extern "C" {
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

// Alignment utilities
#[inline(always)]
pub const fn align_down(x: u64, a: u64) -> u64 {
    if a == 0 || (a & (a - 1)) != 0 { return x; }
    x & !(a - 1)
}

#[inline(always)]
pub const fn align_up(x: u64, a: u64) -> u64 {
    if a == 0 || (a & (a - 1)) != 0 { return x; }
    (x + a - 1) & !(a - 1)
}

#[inline(always)]
pub const fn is_aligned(x: u64, a: u64) -> bool {
    if a == 0 { return false; }
    (x & (a - 1)) == 0
}

#[inline(always)]
pub const fn is_page_aligned(addr: u64) -> bool {
    is_aligned(addr, PAGE_SIZE_U64)
}

// Address space utilities
#[inline(always)]
pub const fn in_kernel_space(va: u64) -> bool {
    va >= CANONICAL_HIGH_MIN
}

#[inline(always)]
pub const fn in_user_space(va: u64) -> bool {
    va <= USER_TOP
}

#[inline(always)]
pub const fn is_canonical(va: u64) -> bool {
    in_user_space(va) || in_kernel_space(va)
}

#[inline(always)]
pub const fn range(base: u64, size: u64) -> Range<u64> {
    base..(base.saturating_add(size))
}

#[inline(always)]
pub const fn selfref_l4_va() -> u64 {
    let i = SELFREF_SLOT as u64;
    (SIGN_EXTEND_MASK << SIGN_EXTEND_SHIFT)
        | (i << PML4_SHIFT)
        | (i << PDPT_SHIFT)
        | (i << PD_SHIFT)
        | (i << PT_SHIFT)
}

// Linker symbol access
pub fn kernel_sections() -> [Section; KERNEL_SECTION_COUNT] {
    // SAFETY: Linker-defined symbols, address calculation only
    unsafe {
        [
            Section { start: &__kernel_text_start as *const _ as u64, end: &__kernel_text_end as *const _ as u64, rx: true, rw: false, nx: false, global: true },
            Section { start: &__kernel_rodata_start as *const _ as u64, end: &__kernel_rodata_end as *const _ as u64, rx: false, rw: false, nx: true, global: true },
            Section { start: &__kernel_data_start as *const _ as u64, end: &__kernel_data_end as *const _ as u64, rx: false, rw: true, nx: true, global: true },
            Section { start: &__kernel_bss_start as *const _ as u64, end: &__kernel_bss_end as *const _ as u64, rx: false, rw: true, nx: true, global: true },
        ]
    }
}

pub fn kernel_start() -> u64 {
    // SAFETY: Linker symbol address calculation only
    unsafe { &__kernel_start as *const _ as u64 }
}

pub fn kernel_end() -> u64 {
    // SAFETY: Linker symbol address calculation only
    unsafe { &__kernel_end as *const _ as u64 }
}

pub fn boot_stacks_region() -> (u64, u64) {
    // SAFETY: Linker symbol address calculation only
    unsafe { (&__boot_stacks_start as *const _ as u64, &__boot_stacks_end as *const _ as u64) }
}

pub fn percpu_template_region() -> (u64, u64) {
    // SAFETY: Linker symbol address calculation only
    unsafe { (&__percpu_start as *const _ as u64, &__percpu_end as *const _ as u64) }
}

// Region utilities
pub fn region_from_firmware(kind_code: u32, start: u64, len: u64) -> Region {
    let kind = match kind_code {
        FIRMWARE_REGION_USABLE => RegionKind::Usable,
        FIRMWARE_REGION_RESERVED => RegionKind::Reserved,
        FIRMWARE_REGION_ACPI_RECLAIM | FIRMWARE_REGION_ACPI_NVS => RegionKind::Acpi,
        FIRMWARE_REGION_MMIO => RegionKind::Mmio,
        _ => RegionKind::Unknown,
    };
    Region::new(start, start.saturating_add(len), kind)
}

pub fn managed_span(regions: &[Region]) -> (u64, u64) {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for region in regions {
        if region.is_usable() {
            let start = align_up(region.start, PAGE_SIZE_U64);
            let end = align_down(region.end, PAGE_SIZE_U64);
            if end > start {
                lo = lo.min(start);
                hi = hi.max(end);
            }
        }
    }
    if lo > hi { (0, 0) } else { (lo, hi) }
}

// KASLR and layout management
pub fn apply_kaslr_slide(slide: u64) -> LayoutResult<()> {
    if !is_page_aligned(slide) {
        return Err(LayoutError::SlideNotAligned);
    }
    let mut layout = LAYOUT.write();
    layout.slide = slide;
    layout.heap_lo = KHEAP_BASE.wrapping_add(slide);
    layout.vm_lo = KVM_BASE.wrapping_add(slide);
    layout.mmio_lo = MMIO_BASE.wrapping_add(slide);
    layout.initialized = true;
    Ok(())
}

#[inline]
pub fn get_slide() -> u64 {
    LAYOUT.read().slide
}

pub fn get_layout() -> LayoutConfig {
    *LAYOUT.read()
}

#[inline]
pub fn is_initialized() -> bool {
    LAYOUT.read().initialized
}

#[inline]
pub fn slid_address(base: u64) -> u64 {
    base.wrapping_add(LAYOUT.read().slide)
}

#[inline]
pub fn slid_range(base: u64, size: u64) -> Range<u64> {
    let b = slid_address(base);
    b..b.saturating_add(size)
}

pub fn validate_layout() -> LayoutResult<()> {
    if KERNEL_BASE < CANONICAL_HIGH_MIN {
        return Err(LayoutError::KernelBaseTooLow);
    }
    if !is_page_aligned(PERCPU_STRIDE) {
        return Err(LayoutError::PercpuStrideMisaligned);
    }

    let layout = LAYOUT.read();
    let slide = layout.slide;
    let pairs: &[(u64, u64, u64, u64)] = &[
        (KTEXT_BASE, KTEXT_SIZE, KDATA_BASE, KDATA_SIZE),
        (KDATA_BASE, KDATA_SIZE, DIRECTMAP_BASE, DIRECTMAP_SIZE),
        (DIRECTMAP_BASE, DIRECTMAP_SIZE, KHEAP_BASE, KHEAP_SIZE),
        (KHEAP_BASE, KHEAP_SIZE, KVM_BASE, KVM_SIZE),
        (KVM_BASE, KVM_SIZE, MMIO_BASE, MMIO_SIZE),
        (MMIO_BASE, MMIO_SIZE, VMAP_BASE, VMAP_SIZE),
    ];

    for &(a_base, a_size, b_base, b_size) in pairs {
        let a_start = a_base.wrapping_add(slide);
        let a_end = a_start.saturating_add(a_size);
        let b_start = b_base.wrapping_add(slide);
        let b_end = b_start.saturating_add(b_size);
        if a_start < b_end && b_start < a_end {
            return Err(LayoutError::WindowOverlap);
        }
        if a_start > b_start {
            return Err(LayoutError::OrderViolation);
        }
    }
    Ok(())
}

pub fn kernel_vaddr_to_phys(vaddr: u64) -> Option<u64> {
    if !in_kernel_space(vaddr) { return None; }
    let slide = LAYOUT.read().slide;
    Some(vaddr.wrapping_sub(slide).wrapping_sub(KERNEL_BASE))
}

pub fn heap_base_for(size: usize) -> LayoutResult<u64> {
    let layout = LAYOUT.read();
    if !layout.initialized { return Err(LayoutError::NotInitialized); }
    let aligned = align_up(layout.heap_lo, PAGE_SIZE_U64);
    if size as u64 > layout.heap_sz { return Err(LayoutError::SizeExceedsCapacity); }
    Ok(aligned)
}

pub fn vm_window() -> (u64, u64) {
    let layout = LAYOUT.read();
    (layout.vm_lo, layout.vm_sz)
}

pub fn mmio_window() -> (u64, u64) {
    let layout = LAYOUT.read();
    (layout.mmio_lo, layout.mmio_sz)
}

pub fn randomize_layout_from_kaslr(policy: kaslr::Policy) -> Result<kaslr::Kaslr, LayoutError> {
    match kaslr::init(policy) {
        Ok(k) => { apply_kaslr_slide(k.slide)?; Ok(k) }
        Err(_) => Err(LayoutError::NotInitialized),
    }
}

// Stack and per-CPU regions
pub fn get_all_stack_regions() -> Vec<StackRegion> {
    let mut regions = Vec::with_capacity((MAX_CPUS as usize) * (1 + IST_STACKS_PER_CPU));
    for cpu_id in 0..MAX_CPUS {
        let stack_base = PERCPU_BASE + (cpu_id as u64) * PERCPU_STRIDE;
        regions.push(StackRegion { base: stack_base, size: KSTACK_SIZE, guard_size: GUARD_PAGES * PAGE_SIZE, cpu_id: Some(cpu_id), thread_id: None });
        for ist_num in 0..IST_STACKS_PER_CPU {
            regions.push(StackRegion { base: stack_base + KSTACK_SIZE as u64 + (ist_num * IST_STACK_SIZE) as u64, size: IST_STACK_SIZE, guard_size: GUARD_PAGES * PAGE_SIZE, cpu_id: Some(cpu_id), thread_id: None });
        }
    }
    regions
}

pub fn get_percpu_regions() -> Vec<PercpuRegion> {
    let mut regions = Vec::with_capacity(MAX_CPUS as usize);
    for cpu_id in 0..MAX_CPUS {
        regions.push(PercpuRegion { base: PERCPU_BASE + (cpu_id as u64) * PERCPU_STRIDE, size: PERCPU_STRIDE as usize, cpu_id });
    }
    regions
}

pub fn get_percpu_region_for(cpu_id: u32) -> Option<PercpuRegion> {
    if cpu_id >= MAX_CPUS { return None; }
    Some(PercpuRegion { base: PERCPU_BASE + (cpu_id as u64) * PERCPU_STRIDE, size: PERCPU_STRIDE as usize, cpu_id })
}

pub fn get_module_regions() -> Vec<ModuleRegion> {
    let mut regions = Vec::with_capacity(KERNEL_SECTION_COUNT);
    for section in kernel_sections().iter() {
        let mut perms = 0u32;
        if section.rx || !section.nx { perms |= PERM_READ; }
        if section.rw { perms |= PERM_WRITE; }
        if section.rx || !section.nx { perms |= PERM_EXEC; }
        regions.push(ModuleRegion { base: section.start, size: section.size() as usize, name: "kernel", permissions: perms });
    }
    regions
}

pub fn log_kernel_sections(mut log: impl FnMut(&str)) {
    for section in kernel_sections().iter() {
        let perm = if section.rx { "RX" } else if section.rw { "RW" } else { "R-" };
        let nx = if section.nx { "NX" } else { "X-" };
        log(&alloc::format!("[layout] {:#016x}-{:#016x} {:>6}KiB {} {} global={}", slid_address(section.start), slid_address(section.end), section.size() / 1024, perm, nx, section.global));
    }
}

pub fn layout_summary() -> alloc::string::String {
    let layout = LAYOUT.read();
    alloc::format!("Layout {{ slide: {:#x}, heap: {:#x}+{:#x}, vm: {:#x}+{:#x}, mmio: {:#x}+{:#x}, init: {} }}", layout.slide, layout.heap_lo, layout.heap_sz, layout.vm_lo, layout.vm_sz, layout.mmio_lo, layout.mmio_sz, layout.initialized)
}
