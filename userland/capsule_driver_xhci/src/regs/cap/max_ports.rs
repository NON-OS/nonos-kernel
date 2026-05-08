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

//! HCSPARAMS1 bits 31:24 — Number of Ports (MaxPorts). USB 2 and
//! USB 3 ports share this count; the per-port USB version is
//! encoded in the Supported Protocol extended capability, not
//! here.

use crate::constants::HCSPARAMS1;
use crate::regs::mmio_read32;

pub fn max_ports(mmio_base: u64) -> u8 {
    ((mmio_read32(mmio_base + HCSPARAMS1) >> 24) & 0xFF) as u8
}
