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

//! Compute the start of one interrupter's register slice.
//! Interrupter 0 lives at runtime_base + 0x20; subsequent
//! interrupters follow at +0x20 each. v1 only programs the
//! primary interrupter (index 0).

use crate::constants::INTERRUPTER_STRIDE;

pub fn interrupter_addr(runtime_base: u64, index: u64) -> u64 {
    runtime_base + INTERRUPTER_STRIDE + index * INTERRUPTER_STRIDE
}
