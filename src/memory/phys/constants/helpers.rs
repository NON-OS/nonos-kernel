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

use super::pages::{BITS_PER_BYTE, PAGE_SIZE_U64};

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
