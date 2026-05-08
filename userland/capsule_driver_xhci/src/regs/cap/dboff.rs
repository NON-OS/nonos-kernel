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

//! Doorbell Array offset. Bottom two bits are reserved-as-zero
//! per the spec; we mask them off. The doorbell array starts at
//! BAR0 + DBOFF; element 0 is the host-controller doorbell
//! (kicks the command ring), elements 1..MaxSlots are the per-
//! slot doorbells (kick endpoint transfer rings).

use crate::constants::DBOFF;
use crate::regs::mmio_read32;

pub fn dboff(mmio_base: u64) -> u64 {
    (mmio_read32(mmio_base + DBOFF) & !0x3) as u64
}
