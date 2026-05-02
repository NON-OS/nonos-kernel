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

use super::super::stats::MMIO_STATS;
use super::accessor::Mmio;
use super::backend;

impl<T: Copy> Mmio<T> {
    /// Single volatile load with no implied ordering relative to other
    /// MMIO or memory accesses.
    #[inline]
    pub fn read_relaxed(&self) -> T {
        MMIO_STATS.record_read();
        // SAFETY: ek@nonos.systems — `from_addr` proved this pointer.
        unsafe { backend::read_relaxed(self.ptr) }
    }

    /// Single volatile store with no implied ordering relative to other
    /// MMIO or memory accesses.
    #[inline]
    pub fn write_relaxed(&self, value: T) {
        MMIO_STATS.record_write();
        // SAFETY: ek@nonos.systems — `from_addr` proved this pointer.
        unsafe { backend::write_relaxed(self.ptr, value) }
    }

    /// Volatile load with acquire ordering against later same-thread
    /// accesses. Cross-CPU acquire-release pairing is not promised; that
    /// belongs to the device protocol the driver implements above.
    #[inline]
    pub fn read_acquire(&self) -> T {
        MMIO_STATS.record_read();
        // SAFETY: ek@nonos.systems — pointer per `from_addr`; the
        // backend supplies the lfence + compiler fence after the load.
        unsafe { backend::read_acquire(self.ptr) }
    }

    /// Volatile store with release ordering against earlier same-thread
    /// accesses. Used for doorbells: prior buffer writes are visible to
    /// the device before the device sees this store. Cross-CPU pairing
    /// is not promised.
    #[inline]
    pub fn write_release(&self, value: T) {
        MMIO_STATS.record_write();
        // SAFETY: ek@nonos.systems — pointer per `from_addr`; the
        // backend supplies the compiler fence + sfence before the store.
        unsafe { backend::write_release(self.ptr, value) }
    }
}
