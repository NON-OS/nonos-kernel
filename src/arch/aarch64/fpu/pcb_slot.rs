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

use super::slot::FpSimdSlot;

// PCB-owned FP/SIMD slot. UnsafeCell because the slot is mutated in
// trap context with traps masked; the task runs on at most one CPU at
// a time, so the only writer is the kernel handler for that task and
// no locking is needed. Marker Sync makes the cell embeddable in a PCB
// that is itself Sync (held in PROCESS_TABLE via Arc).
#[repr(transparent)]
pub struct PcbArchFpu {
    inner: UnsafeCell<FpSimdSlot>,
}

// SAFETY: at any moment, the inner cell is accessed only on the CPU
// running the task that owns the enclosing PCB; aliasing is impossible
// because a task is not migrated mid-handler. The pointer returned by
// `slot_ptr` is read by `fpu::current::slot_mut` from that same CPU's
// trap path.
unsafe impl Sync for PcbArchFpu {}

impl PcbArchFpu {
    pub const fn zeroed() -> Self {
        Self { inner: UnsafeCell::new(FpSimdSlot::zeroed()) }
    }

    // Stable address for as long as the enclosing PCB lives in
    // PROCESS_TABLE. Callers must hold the trap-context invariant.
    pub fn slot_ptr(&self) -> *mut FpSimdSlot {
        self.inner.get()
    }
}
