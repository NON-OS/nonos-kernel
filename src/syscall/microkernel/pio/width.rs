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

//! Decode the userland-supplied PIO width argument. The wire
//! contract is bytes-per-access (1, 2, 4); anything else is
//! rejected before the broker is touched.

use crate::hardware::broker::PioWidth;

pub(super) fn from_arg(w: u64) -> Option<PioWidth> {
    match w {
        1 => Some(PioWidth::U8),
        2 => Some(PioWidth::U16),
        4 => Some(PioWidth::U32),
        _ => None,
    }
}
