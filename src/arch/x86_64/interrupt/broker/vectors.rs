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

//! Broker IRQ vector range. 64 vectors are reserved out of the
//! IDT for `MkIrqBind` grants. Both legacy INTx routes and
//! MSI/MSI-X routes terminate in this pool; the dispatcher does
//! not care which programming path delivered the vector.
//!
//! IDT layout this pool sits inside:
//!
//!   0x00..0x1F  CPU exceptions
//!   0x20        APIC timer
//!   0x21..0x2F  legacy PIC-remapped IRQs (PS/2, ATA, RTC, ...)
//!   0x30..0x7E  IO-APIC dynamic pool (kernel-internal)
//!   0x7F        unused
//!   0x80        SYSCALL trap gate (DPL=3)
//!   0x81..0xC0  broker IRQ pool (this module)
//!   0xC1..0xF9  unused
//!   0xFA..0xFE  APIC LVT declared range
//!   0xFF        APIC spurious vector
//!
//! The pool is contiguous so MSI-X allocations of N vectors get
//! N consecutive grants when the slot allocator finds room.

pub const BROKER_VEC_MIN: u8 = 0x81;
pub const BROKER_VEC_MAX: u8 = 0xC0;
pub const BROKER_VEC_COUNT: usize = (BROKER_VEC_MAX - BROKER_VEC_MIN + 1) as usize;

#[inline]
pub const fn slot_of(vector: u8) -> Option<usize> {
    if vector >= BROKER_VEC_MIN && vector <= BROKER_VEC_MAX {
        Some((vector - BROKER_VEC_MIN) as usize)
    } else {
        None
    }
}

#[inline]
pub const fn vector_of(slot: usize) -> Option<u8> {
    if slot < BROKER_VEC_COUNT {
        Some(BROKER_VEC_MIN + slot as u8)
    } else {
        None
    }
}

// Refuse to build if the pool overlaps a kernel-private vector
// or undershoots the documented 64-vector size.
const _: () = {
    assert!(BROKER_VEC_MIN > 0x80, "broker pool must sit above SYSCALL vector");
    assert!(BROKER_VEC_MAX < 0xFA, "broker pool must sit below APIC LVT range");
    assert!(BROKER_VEC_COUNT == 64, "broker pool must expose 64 vectors");
};
