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

//! The states the proofs draw widgets in.

use nonos_toolkit::widgets::State;

/// Every combination of the five state flags, the default first.
pub(crate) fn states() -> impl Iterator<Item = State> {
    (0u8..32).map(|b| State {
        hovered: b & 1 != 0,
        focused: b & 2 != 0,
        pressed: b & 4 != 0,
        selected: b & 8 != 0,
        disabled: b & 16 != 0,
    })
}

/// The states whose look differs under the ink: hovered, pressed and selected
/// alone and together, focus alone and on top of them all, and disabled alone
/// and with everything else.
pub(crate) fn looks() -> impl Iterator<Item = State> {
    let live = (0u8..8).map(|b| (b & 1 != 0, b & 2 != 0, b & 4 != 0, false, false));
    let more = [(false, false, false, true, false), (true, true, true, true, false)];
    let off = [(false, false, false, false, true), (true, true, true, true, true)];
    let all = live.chain(more).chain(off);
    all.map(|(hovered, pressed, selected, focused, disabled)| State {
        hovered,
        focused,
        pressed,
        selected,
        disabled,
    })
}
