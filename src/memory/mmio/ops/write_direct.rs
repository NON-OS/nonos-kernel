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
pub fn mmio_w8(va: VirtAddr, value: u8) {
    // SAFETY: ek@nonos.systems
    // Single-byte stores are the most permissive case at the bus level —
    // no alignment to satisfy, no width split possible. The helper is
    // typically used for legacy device control bytes where the register
    // protocol is straightforward and side effects are limited.
    unsafe { Mmio::<u8>::from_addr(va) }.write_relaxed(value);
}

#[inline]
pub fn mmio_w16(va: VirtAddr, value: u16) {
    // SAFETY: ek@nonos.systems
    // The address must be 2-byte aligned. Some 16-bit device registers
    // expect exactly word-wide writes and behave undefined on byte-pair
    // accesses; the caller is on the hook for matching the register's
    // declared write width. Half-word MMIO is rarer than 32-bit but
    // common in older controllers.
    unsafe { Mmio::<u16>::from_addr(va) }.write_relaxed(value);
}

#[inline]
pub fn mmio_w32(va: VirtAddr, value: u32) {
    // SAFETY: ek@nonos.systems
    // Most doorbell, command-submission, and control-register updates are
    // 32-bit. The store has device-visible side effects in many cases —
    // writing the doorbell starts work — so a real driver almost always
    // wants `write_release` here, not the relaxed form. The helper exists
    // because legacy call sites already use the function-call form.
    unsafe { Mmio::<u32>::from_addr(va) }.write_relaxed(value);
}

#[inline]
pub fn mmio_w64(va: VirtAddr, value: u64) {
    // SAFETY: ek@nonos.systems
    // x86_64 issues a naturally-aligned 64-bit store as a single bus
    // transaction; lesser CPUs would split it into two 32-bit writes,
    // which is why this helper is x86-shaped today. The address must be
    // 8-byte aligned and the device must accept a one-shot 64-bit write
    // at this offset; some controllers explicitly require two 32-bit
    // halves and will misbehave under a 64-bit access.
    unsafe { Mmio::<u64>::from_addr(va) }.write_relaxed(value);
}
