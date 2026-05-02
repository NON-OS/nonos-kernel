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
use crate::memory::mmio::ordering::Mmio;

#[inline]
pub fn mmio_r8(va: VirtAddr) -> u8 {
    // SAFETY: ek@nonos.systems
    // Eight-bit MMIO loads have no alignment concern beyond `va` being
    // non-null and inside a kernel-mapped device page. The legacy
    // contract is that the caller hands over an address it has already
    // mapped; the constructor consumes that promise for one volatile
    // byte read.
    unsafe { Mmio::<u8>::from_addr(va) }.read_relaxed()
}

#[inline]
pub fn mmio_r16(va: VirtAddr) -> u16 {
    // SAFETY: ek@nonos.systems
    // The address must be 2-byte aligned; PCI configuration registers and
    // most 16-bit device registers naturally satisfy that. Misalignment
    // here is a real bug — on x86 it costs a split bus cycle and on the
    // other targets it faults outright — but the helper does not check.
    unsafe { Mmio::<u16>::from_addr(va) }.read_relaxed()
}

#[inline]
pub fn mmio_r32(va: VirtAddr) -> u32 {
    // SAFETY: ek@nonos.systems
    // Thirty-two bits is the dominant MMIO register width in this kernel
    // — NVMe doorbells, virtio common configuration, BAR-mapped control
    // registers all sit here. The address must be 4-byte aligned, which
    // hardware always honors when the register is exposed at its
    // architectural offset.
    unsafe { Mmio::<u32>::from_addr(va) }.read_relaxed()
}

#[inline]
pub fn mmio_r64(va: VirtAddr) -> u64 {
    // SAFETY: ek@nonos.systems
    // Sixty-four-bit MMIO loads require an 8-byte-aligned address and a
    // CPU capable of issuing a single 64-bit transaction; x86_64 does so
    // natively. NVMe SQ/CQ doorbell pairs and certain APIC registers are
    // the typical 64-bit-wide consumers. Some hardware splits a 64-bit
    // load into two 32-bit transactions even when issued atomically —
    // that is the device's contract, not the helper's.
    unsafe { Mmio::<u64>::from_addr(va) }.read_relaxed()
}
