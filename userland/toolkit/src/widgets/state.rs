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

//! What the app tells a widget about its current condition.

/// What the app tells a widget about it. The app owns it and sets it from input.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct State {
    /// The pointer is over the widget.
    pub hovered: bool,
    /// The widget has keyboard focus.
    pub focused: bool,
    /// The pointer or key is held down on the widget.
    pub pressed: bool,
    /// The widget is the chosen one in its group.
    pub selected: bool,
    /// The widget ignores input and draws as unavailable.
    pub disabled: bool,
}
