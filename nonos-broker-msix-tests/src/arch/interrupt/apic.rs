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

//! Host fixture for `crate::arch::interrupt::apic`. The kernel's
//! `bind_intx` reads the local APIC id and writes it into the
//! IO-APIC redirection entry; the host test fixture returns the
//! BSP id (0) so the recorded routes match a deterministic
//! destination across runs.

pub fn id() -> u32 {
    0
}
