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

use super::state::CommandRing;

impl CommandRing {
    /// Encode the ring's base address + initial RCS bit for the
    /// CRCR write at init. The low six bits of the base must be
    /// zero (the broker hands back 64-byte-aligned grants so this
    /// is already true; the mask is defensive).
    pub fn crcr_value(&self) -> u64 {
        (self.region.phys() & !0x3F) | (self.cycle as u64 & 0x1)
    }
}
