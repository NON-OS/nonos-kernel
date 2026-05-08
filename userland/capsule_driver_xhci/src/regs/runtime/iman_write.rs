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

//! Write the per-interrupter Management register. Used to set IE
//! at init and to clear the IP latch (write-1-to-clear) after
//! the completion handler has drained the event ring.

use crate::constants::IMAN;
use crate::regs::mmio_write32;

pub fn iman_write(intr_base: u64, value: u32) {
    mmio_write32(intr_base + IMAN, value);
}
