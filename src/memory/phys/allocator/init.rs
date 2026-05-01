// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::constants::{
    align_down, align_up, bitmap_bytes_for_frames, frames_in_range, PAGE_SIZE_U64,
};
use super::super::error::{PhysAllocError, PhysAllocResult};
use super::super::types::AllocatorState;
use super::random::derive_seed;
use core::ptr;
use crate::memory::addr::PhysAddr;

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
    unsafe {
        ptr::write_bytes(bitmap_ptr, 0, required_bytes);
    }
    Ok(())
}
