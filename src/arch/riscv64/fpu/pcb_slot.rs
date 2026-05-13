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

use core::cell::UnsafeCell;

use super::slot::FpSlot;

// PCB-owned F/D-extension slot. UnsafeCell because the slot is mutated
// in trap context with SIE masked; the task runs on at most one hart
// at a time, so the only writer is the kernel handler for that task
// and no locking is needed. Sync for embedding in PCB which is Sync.
#[repr(transparent)]
pub struct PcbArchFpu {
    inner: UnsafeCell<FpSlot>,
}

// SAFETY: the cell is accessed only on the hart running the task that
// owns the enclosing PCB; aliasing is impossible because tasks are not
// migrated mid-handler. `slot_ptr` is read from the same hart's lazy-
// enable trap path.
unsafe impl Sync for PcbArchFpu {}

impl PcbArchFpu {
    pub const fn zeroed() -> Self {
        Self { inner: UnsafeCell::new(FpSlot::zeroed()) }
    }

    pub fn slot_ptr(&self) -> *mut FpSlot {
        self.inner.get()
    }
}
