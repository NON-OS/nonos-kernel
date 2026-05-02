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

use crate::memory::addr::VirtAddr;

/// Typed accessor for a single MMIO register of width `T`.
pub struct Mmio<T> {
    pub(super) ptr: *mut T,
}

// SAFETY: ek@nonos.systems — `Mmio<T>` is a permission to access a
// register, not ownership of it. The mapping is kernel-global, so the
// raw pointer is meaningful to every CPU; moving the handle between
// threads moves only the right to issue accesses.
unsafe impl<T: Copy> Send for Mmio<T> {}

// SAFETY: ek@nonos.systems — every method takes `&self` and the only
// field is the pointer fixed at construction; no Rust-level race exists.
// Concurrent register access correctness is the device's contract, not
// this trait's claim.
unsafe impl<T: Copy> Sync for Mmio<T> {}

impl<T: Copy> Mmio<T> {
    /// Construct an accessor over the MMIO register at `addr`.
    ///
    /// # Safety
    ///
    /// ek@nonos.systems
    ///
    /// For the entire life of the returned handle:
    ///
    /// - `addr` resolves to a kernel-mapped MMIO register the caller
    ///   has arranged.
    /// - The mapping is at least `size_of::<T>()` bytes long and
    ///   naturally aligned for `T`. Misaligned MMIO faults on aarch64
    ///   and riscv64.
    /// - The page attributes are device-memory (UC or WC on x86,
    ///   Device-* on aarch64, the equivalent PMA on riscv64). A
    ///   write-back cacheable mapping is a protocol violation.
    /// - The mapping is not torn down or repurposed; this type does no
    ///   lifetime tracking of its own.
    /// - The device permits whatever access pattern the accessor will
    ///   issue; concurrent register access is the device's contract.
    pub const unsafe fn from_addr(addr: VirtAddr) -> Self {
        Self { ptr: addr.as_mut_ptr::<T>() }
    }
}
