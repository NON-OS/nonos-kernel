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

use super::backend;

/// Witness that the contract precondition held at construction time.
/// The only constructor is `acquire`; the inner field is private, so
/// nothing outside this module can mint one.
pub struct SwitchLease {
    _seal: (),
}

impl SwitchLease {
    /// Returns `Some` only when interrupts are disabled on the calling
    /// CPU. A switch with interrupts on would race the trap path.
    pub fn acquire() -> Option<Self> {
        if backend::interrupts_enabled() {
            return None;
        }
        Some(Self { _seal: () })
    }
}
