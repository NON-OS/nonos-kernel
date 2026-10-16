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

//! The held look every pressable widget shares.

use crate::theme::derive::away;
use crate::theme::Opaque;

/// How far a held fill moves, out of 255.
const PRESS: u8 = 32;

/// `fill` as it looks while held: moved away from `ink`, darker under a light
/// ink and lighter under a dark one, so pressing never lowers the ink's
/// contrast.
pub fn pressed(fill: Opaque, ink: Opaque) -> Opaque {
    Opaque::new(away(fill.argb(), ink.argb(), PRESS))
}
