// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use super::super::constants::*;
use super::super::error::{LayoutError, LayoutResult};
use super::super::types::LayoutConfig;
use super::address::in_kernel_space;
use super::align::is_page_aligned;
use super::state::LAYOUT;
use crate::memory::kaslr;
use core::ops::Range;

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
        let (a_s, a_e) =
            (a_base.wrapping_add(slide), a_base.wrapping_add(slide).saturating_add(a_size));
        let (b_s, b_e) =
            (b_base.wrapping_add(slide), b_base.wrapping_add(slide).saturating_add(b_size));
        if a_s < b_e && b_s < a_e {
            return Err(LayoutError::WindowOverlap);
        }
        if a_s > b_s {
            return Err(LayoutError::OrderViolation);
        }
    }
    Ok(())
}

pub fn kernel_vaddr_to_phys(vaddr: u64) -> Option<u64> {
    if !in_kernel_space(vaddr) {
        return None;
    }
    Some(vaddr.wrapping_sub(LAYOUT.read().slide).wrapping_sub(KERNEL_BASE))
}
pub fn heap_base_for(size: usize) -> LayoutResult<u64> {
    let layout = LAYOUT.read();
    if !layout.initialized {
        return Err(LayoutError::NotInitialized);
    }
    let aligned = super::align::align_up(layout.heap_lo, PAGE_SIZE_U64);
    if size as u64 > layout.heap_sz {
        return Err(LayoutError::SizeExceedsCapacity);
    }
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
        Ok(k) => {
            apply_kaslr_slide(k.slide)?;
            Ok(k)
        }
        Err(_) => Err(LayoutError::NotInitialized),
    }
}
