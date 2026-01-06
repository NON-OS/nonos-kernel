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

use core::ptr;
use x86_64::PhysAddr;
use super::bitmap;
use super::constants::*;
use super::error::{PhysAllocError, PhysAllocResult};
use super::types::{AllocFlags, AllocatorState, Frame, ZoneStats};
use crate::memory::layout;
// ============================================================================
// RANDOMIZATION
// ============================================================================
pub fn derive_seed() -> u64 {
    if let Ok(nonce) = crate::memory::kaslr::boot_nonce() {
        nonce.wrapping_add(SPLITMIX64_GOLDEN)
    } else {
        FALLBACK_SEED
    }
}

#[inline]
pub fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX64_MIX1);
    z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX64_MIX2);
    z ^ (z >> 31)
}

// ============================================================================
// FRAME ZEROING
// ============================================================================
/// ## Safety
/// This function accesses physical memory through the direct map.
/// The frame must be within the managed range.
pub fn zero_frame(frame: Frame) {
    let pa = frame.addr();
    let dm_base = layout::DIRECTMAP_BASE;
    let dm_size = layout::DIRECTMAP_SIZE;

    // Bounds check
    if pa >= dm_size {
        return;
    }

    let va = dm_base.wrapping_add(pa);
    if va < dm_base {
        return;
    }

    if va.wrapping_add(PAGE_SIZE_U64) > dm_base.wrapping_add(dm_size) {
        return;
    }
    // SAFETY: Address is within direct map bounds, writing zeros is safe
    unsafe {
        let ptr = va as *mut u8;
        ptr::write_bytes(ptr, 0, PAGE_SIZE);
    }
}
// ============================================================================
// ALLOCATOR OPERATIONS
// ============================================================================
pub fn init_with_bitmap(
    state: &mut AllocatorState,
    managed_start: PhysAddr,
    managed_end: PhysAddr,
    bitmap_ptr: *mut u8,
    bitmap_bytes: usize,
) -> PhysAllocResult<()> {
    if managed_end.as_u64() <= managed_start.as_u64() {
        return Err(PhysAllocError::InvalidRange);
    }

    let aligned_start = align_up(managed_start.as_u64(), PAGE_SIZE_U64);
    let aligned_end = align_down(managed_end.as_u64(), PAGE_SIZE_U64);
    if aligned_end <= aligned_start {
        return Err(PhysAllocError::NoCompletePagesInRange);
    }

    let frame_count = frames_in_range(aligned_start, aligned_end);
    let required_bytes = bitmap_bytes_for_frames(frame_count);
    if bitmap_bytes < required_bytes {
        return Err(PhysAllocError::BitmapTooSmall);
    }

    if bitmap_ptr.is_null() {
        return Err(PhysAllocError::InvalidBitmapPointer);
    }

    state.frame_start = aligned_start;
    state.frame_count = frame_count;
    state.bitmap_ptr = bitmap_ptr;
    state.bitmap_bytes = bitmap_bytes;
    state.next_hint = 0;
    state.random_seed = derive_seed();
    // SAFETY: bitmap_ptr is valid and we've verified it has enough space
    unsafe {
        ptr::write_bytes(bitmap_ptr, 0, required_bytes);
    }
    Ok(())
}

pub fn allocate_frame(state: &mut AllocatorState, flags: AllocFlags) -> Option<Frame> {
    if !state.is_initialized() {
        return None;
    }

    let bptr = state.bitmap_ptr;
    let total = state.frame_count;
    let start = state.frame_start;
    if flags.contains(AllocFlags::HIGH) {
        for i in (0..total).rev() {
            // SAFETY: i < total, and bitmap is properly sized
            if unsafe { !bitmap::bit_test(bptr, i) } {
                unsafe { bitmap::bit_set(bptr, i) };
                state.next_hint = i as u64;
                let pa = start.wrapping_add((i as u64).wrapping_mul(PAGE_SIZE_U64));
                let frame = Frame::new(pa);
                if flags.contains(AllocFlags::ZERO) {
                    zero_frame(frame);
                }

                return Some(frame);
            }
        }
        return None;
    }

    state.random_seed = state.random_seed.wrapping_add(1);
    let rnd = state.random_seed;
    let hint = state.next_hint as usize;
    let idx0 = (mix64(rnd) as usize).wrapping_add(hint) % total;
    for offset in 0..total {
        let i = (idx0 + offset) % total;
        // SAFETY: i < total, and bitmap is properly sized
        if unsafe { !bitmap::bit_test(bptr, i) } {
            unsafe { bitmap::bit_set(bptr, i) };
            state.next_hint = i as u64;
            let pa = start.wrapping_add((i as u64).wrapping_mul(PAGE_SIZE_U64));
            let frame = Frame::new(pa);
            if flags.contains(AllocFlags::ZERO) {
                zero_frame(frame);
            }

            return Some(frame);
        }
    }

    None
}

pub fn deallocate_frame(state: &mut AllocatorState, frame: Frame) -> PhysAllocResult<()> {
    if !state.is_initialized() {
        return Err(PhysAllocError::NotInitialized);
    }

    let start = state.frame_start;
    let total = state.frame_count;
    let bptr = state.bitmap_ptr;
    if frame.addr() < start {
        return Err(PhysAllocError::AddressBelowRange);
    }

    let offset = frame.addr().saturating_sub(start);
    if offset % PAGE_SIZE_U64 != 0 {
        return Err(PhysAllocError::AddressNotAligned);
    }

    let idx = (offset / PAGE_SIZE_U64) as usize;
    if idx >= total {
        return Err(PhysAllocError::AddressAboveRange);
    }
    // SAFETY: idx < total, bitmap is valid
    if unsafe { !bitmap::bit_test(bptr, idx) } {
        return Err(PhysAllocError::DoubleFree);
    }
    // SAFETY: idx < total, bitmap is valid
    unsafe { bitmap::bit_clear(bptr, idx) };

    Ok(())
}

pub fn allocate_contiguous(
    state: &mut AllocatorState,
    frame_count: usize,
    flags: AllocFlags,
) -> Option<u64> {
    if frame_count == 0 || !state.is_initialized() {
        return None;
    }

    let total = state.frame_count;
    if frame_count > total {
        return None;
    }

    let bptr = state.bitmap_ptr;
    let start = state.frame_start;
    // SAFETY: bitmap is valid and total is correct
    let run_start = unsafe { bitmap::find_contiguous_free(bptr, total, frame_count)? };
    // SAFETY: run_start + frame_count <= total
    unsafe { bitmap::set_bit_range(bptr, run_start, frame_count) };

    let phys_addr = start.wrapping_add((run_start as u64).wrapping_mul(PAGE_SIZE_U64));
    if flags.contains(AllocFlags::ZERO) {
        for j in 0..frame_count {
            let frame_pa = phys_addr + (j as u64 * PAGE_SIZE_U64);
            zero_frame(Frame::new(frame_pa));
        }
    }

    Some(phys_addr)
}

pub fn free_contiguous(
    state: &mut AllocatorState,
    phys_addr: u64,
    frame_count: usize,
) -> PhysAllocResult<()> {
    if frame_count == 0 {
        return Ok(());
    }

    if !state.is_initialized() {
        return Err(PhysAllocError::NotInitialized);
    }

    let start = state.frame_start;
    let total = state.frame_count;
    if phys_addr < start {
        return Err(PhysAllocError::AddressBelowRange);
    }

    let offset = phys_addr.saturating_sub(start);
    if offset % PAGE_SIZE_U64 != 0 {
        return Err(PhysAllocError::AddressNotAligned);
    }

    let start_idx = (offset / PAGE_SIZE_U64) as usize;
    if start_idx + frame_count > total {
        return Err(PhysAllocError::RangeBeyondManaged);
    }

    let bptr = state.bitmap_ptr;
    // SAFETY: indices are within bounds
    if !unsafe { bitmap::is_range_allocated(bptr, start_idx, frame_count) } {
        return Err(PhysAllocError::DoubleFree);
    }
    // SAFETY: indices are within bounds
    unsafe { bitmap::clear_bit_range(bptr, start_idx, frame_count) };

    Ok(())
}

pub fn get_zone_stats(state: &AllocatorState) -> ZoneStats {
    if !state.is_initialized() {
        return ZoneStats::new(0, 0);
    }
    // SAFETY: state is initialized, bitmap is valid
    let free = unsafe { bitmap::count_free_bits(state.bitmap_ptr, state.frame_count) };

    ZoneStats::new(state.frame_count, free)
}

pub fn managed_range(state: &AllocatorState) -> (u64, u64) {
    let start = state.frame_start;
    let end = start + ((state.frame_count as u64) * PAGE_SIZE_U64);
    (start, end)
}

pub fn total_memory(state: &AllocatorState) -> u64 {
    (state.frame_count * PAGE_SIZE) as u64
}

// ============================================================================
// GLOBAL STATE
// ============================================================================
extern crate alloc;
use spin::Mutex;
static ALLOCATOR: Mutex<AllocatorState> = Mutex::new(AllocatorState::new());
// ============================================================================
// PUBLIC API
// ============================================================================
pub fn phys_init_with_bitmap(
    managed_start: PhysAddr,
    managed_end: PhysAddr,
    bitmap_ptr: *mut u8,
    bitmap_bytes: usize,
) -> PhysAllocResult<()> {
    let mut state = ALLOCATOR.lock();
    init_with_bitmap(&mut state, managed_start, managed_end, bitmap_ptr, bitmap_bytes)
}

pub fn phys_init(managed_start: PhysAddr, managed_end: PhysAddr) -> PhysAllocResult<()> {
    let size = ((managed_end.as_u64().saturating_sub(managed_start.as_u64())) as usize / PAGE_SIZE)
        + BITS_PER_BYTE;
    let bytes = bitmap_bytes_for_frames(size);
    let mut v = alloc::vec::Vec::new();
    v.resize(bytes, 0u8);
    let bptr = v.leak().as_mut_ptr();
    phys_init_with_bitmap(managed_start, managed_end, bptr, bytes)
}

pub fn phys_allocate_frame(flags: AllocFlags) -> Option<Frame> {
    let mut state = ALLOCATOR.lock();
    allocate_frame(&mut state, flags)
}

pub fn phys_deallocate_frame(frame: Frame) -> PhysAllocResult<()> {
    let mut state = ALLOCATOR.lock();
    deallocate_frame(&mut state, frame)
}

pub fn phys_alloc_contiguous(frame_count: usize, flags: AllocFlags) -> Option<u64> {
    let mut state = ALLOCATOR.lock();
    allocate_contiguous(&mut state, frame_count, flags)
}

pub fn phys_free_contiguous(phys_addr: u64, frame_count: usize) -> PhysAllocResult<()> {
    let mut state = ALLOCATOR.lock();
    free_contiguous(&mut state, phys_addr, frame_count)
}

#[inline]
pub fn phys_alloc(flags: AllocFlags) -> Option<Frame> {
    phys_allocate_frame(flags)
}

#[inline]
pub fn phys_free(frame: Frame) -> PhysAllocResult<()> {
    phys_deallocate_frame(frame)
}

pub fn phys_zone_stats() -> alloc::vec::Vec<(u32, ZoneStats)> {
    let state = ALLOCATOR.lock();
    let stats = get_zone_stats(&state);
    alloc::vec![(0, stats)]
}

pub fn phys_total_free_frames() -> usize {
    let state = ALLOCATOR.lock();
    get_zone_stats(&state).frames_free
}

pub fn phys_total_memory() -> u64 {
    let state = ALLOCATOR.lock();
    total_memory(&state)
}

pub fn phys_managed_range() -> (u64, u64) {
    let state = ALLOCATOR.lock();
    managed_range(&state)
}

pub fn phys_is_initialized() -> bool {
    ALLOCATOR.lock().is_initialized()
}
