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

//! Volatile TRB read against a 16-byte-aligned address. The DMA
//! buffer is shared with the controller; without a volatile read
//! the optimiser is free to assume the underlying memory is
//! unchanged across observations.

use super::base::Trb;

pub fn read_volatile_at(slot_va: u64) -> Trb {
    unsafe { core::ptr::read_volatile(slot_va as *const Trb) }
}
