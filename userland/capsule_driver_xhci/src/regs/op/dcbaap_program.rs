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

//! Program the Device Context Base Address Array Pointer. Bits
//! 5:0 are reserved-as-zero (the array is 64-byte aligned), so
//! caller is responsible for passing a properly aligned address;
//! the mask clamps it just to be safe.

use crate::constants::DCBAAP_LO;
use crate::regs::mmio_write64;

pub fn dcbaap_program(op_base: u64, dcbaa_phys: u64) {
    mmio_write64(op_base + DCBAAP_LO, dcbaa_phys & !0x3F);
}
