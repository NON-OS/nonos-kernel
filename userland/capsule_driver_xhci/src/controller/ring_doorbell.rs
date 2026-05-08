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

//! Kick a doorbell. Slot 0 / target 0 is the host doorbell that
//! tells the controller to fetch from the command ring. Per-slot
//! transfer doorbells (slot N, target = DCI) are P1+ work and
//! not exposed here.

use crate::regs::mmio_write32;

pub fn ring_doorbell(doorbell_base: u64, slot: u8, target: u8) {
    let addr = doorbell_base + (slot as u64) * 4;
    mmio_write32(addr, target as u32);
}
