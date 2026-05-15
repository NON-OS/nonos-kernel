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

//! Read the used ring after the device finishes the descriptor
//! chain, plus accessors for the trailing status byte and the data
//! buffer the device wrote into.

use core::ptr::read_volatile;

use super::layout::Queue;
use crate::constants::STATUS_OFFSET;

const USED_IDX_OFFSET: usize = 2;

impl Queue {
    /// Snapshot of the device's `used.idx`. The capsule compares
    /// it to `last_used` to detect a completion.
    pub fn used_idx(&self) -> u16 {
        unsafe { read_volatile(self.region_va.add(self.used_offset + USED_IDX_OFFSET).cast()) }
    }

    /// Read the trailing status byte the device wrote at the end
    /// of the descriptor chain.
    pub fn status_byte(&self) -> u8 {
        unsafe { read_volatile(self.header_va.add(STATUS_OFFSET)) }
    }

    /// Borrow the data buffer with a hard upper bound. `len` is
    /// trusted up to `data_len`; a misbehaving device cannot cause
    /// the caller to read past the DMA grant.
    ///
    /// # Safety
    /// `len` must be the byte count the caller posted in the data
    /// descriptor, and the queue must not have a request in flight
    /// while the slice is held.
    pub unsafe fn data(&self, len: u32) -> &[u8] {
        let n = core::cmp::min(len, self.data_len) as usize;
        core::slice::from_raw_parts(self.data_va, n)
    }

    /// Mutable view of the data buffer, used by the write path to
    /// stage payload bytes before the request is posted.
    ///
    /// # Safety
    /// Same constraints as [`Queue::data`].
    pub unsafe fn data_mut(&self, len: u32) -> &mut [u8] {
        let n = core::cmp::min(len, self.data_len) as usize;
        core::slice::from_raw_parts_mut(self.data_va, n)
    }
}
