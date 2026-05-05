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

//! Broker IRQ vector range. Sixteen vectors are reserved out of the
//! IO-APIC pool for `MkIrqBind` grants. The kernel's other IRQ
//! consumers (timer, keyboard, mouse, APIC LVT, syscall) sit
//! outside this window.

pub const BROKER_VEC_MIN: u8 = 0x60;
pub const BROKER_VEC_MAX: u8 = 0x6F;
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
