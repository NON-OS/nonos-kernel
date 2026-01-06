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
// ============================================================================
// PAGE SIZE CONSTANTS
// ============================================================================
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;
pub const BITS_PER_BYTE: usize = 8;
// ============================================================================
// BITMAP CONSTANTS
// ============================================================================
pub const MAX_PHYSICAL_MEMORY: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_FRAME_COUNT: usize = (MAX_PHYSICAL_MEMORY / PAGE_SIZE_U64) as usize;
pub const MAX_BITMAP_SIZE: usize = MAX_FRAME_COUNT / BITS_PER_BYTE;
// ============================================================================
// RANDOMIZATION CONSTANTS
// ============================================================================
pub const SPLITMIX64_GOLDEN: u64 = 0x9e3779b97f4a7c15;
pub const SPLITMIX64_MIX1: u64 = 0xbf58476d1ce4e5b9;
pub const SPLITMIX64_MIX2: u64 = 0x94d049bb133111eb;
pub const FALLBACK_SEED: u64 = 0x1337deadbeef4242;
// ============================================================================
// ALIGNMENT HELPERS
// ============================================================================
#[inline]
pub const fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    ((value + align - 1) / align) * align
}

#[inline]
pub const fn align_down(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    (value / align) * align
}

#[inline]
pub const fn bitmap_bytes_for_frames(frame_count: usize) -> usize {
    (frame_count + BITS_PER_BYTE - 1) / BITS_PER_BYTE
}

#[inline]
pub const fn frames_in_range(start: u64, end: u64) -> usize {
    if end <= start {
        return 0;
    }
    ((end - start) / PAGE_SIZE_U64) as usize
}
