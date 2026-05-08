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

//! `Drainer` carries the prefix-state across drain cycles. The
//! E0 / E1 prefix bytes appear on a separate IRQ from the actual
//! key code, so the drainer remembers "we just saw an E0" until
//! the next byte arrives.

pub struct Drainer {
    pub(super) pending_e0: bool,
    pub(super) pending_e1: bool,
}

impl Drainer {
    pub const fn new() -> Self {
        Self { pending_e0: false, pending_e1: false }
    }
}
