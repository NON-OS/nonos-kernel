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

//! HCCPARAMS1 bit 0 — 64-bit Addressing Capability. The capsule
//! refuses to operate on a controller without this bit because
//! the v1 init programs CRCR/DCBAAP/ERSTBA/ERDP as single 64-bit
//! transactions. A 32-bit-only controller would need a split-
//! access path that this slice does not implement.

use crate::constants::HCCPARAMS1;
use crate::regs::mmio_read32;

pub fn ac64(mmio_base: u64) -> bool {
    (mmio_read32(mmio_base + HCCPARAMS1) & 0x1) != 0
}
