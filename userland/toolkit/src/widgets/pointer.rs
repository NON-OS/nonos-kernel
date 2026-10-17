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
//! Where the pointer is and what it holds, as the State a widget draws. The
//! toolkit cannot see the skeleton's input events, so the app passes them in.

use super::State;

/// The pointer over one window, where a held press began, and whether a finger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Pointer {
    at: Option<(i32, i32)>,
    began: Option<(i32, i32)>,
    touch: bool,
}

impl Pointer {
    /// A pointer that has not been seen yet, so nothing is hovered.
    pub const fn new() -> Self {
        Pointer { at: None, began: None, touch: false }
    }

    /// The pointer moved to `(x, y)`, in content coordinates.
    pub fn moved(&mut self, x: i32, y: i32) {
        self.at = Some((x, y));
    }

    /// A button went down at `(x, y)`.
    pub fn pressed(&mut self, x: i32, y: i32) {
        *self = Pointer { at: Some((x, y)), began: Some((x, y)), touch: false };
    }

    /// A finger came down at `(x, y)`: a press with no hover before or after.
    pub fn touched(&mut self, x: i32, y: i32) {
        *self = Pointer { at: Some((x, y)), began: Some((x, y)), touch: true };
    }

    /// The button or the finger came up. A finger leaves nothing hovered.
    pub fn released(&mut self) {
        self.began = None;
        if self.touch {
            *self = Pointer::new();
        }
    }

    /// The pointer left the window, so nothing under it is hovered.
    pub fn left(&mut self) {
        *self = Pointer::new();
    }

    /// Where the pointer is, if it is over the window.
    pub fn position(&self) -> Option<(i32, i32)> {
        self.at
    }

    /// The hover and press a widget draws, given its hit test: pressed only while
    /// a press that began on it is held there, so one dragged off clicks nothing.
    pub fn state(&self, hit: impl Fn(i32, i32) -> bool) -> State {
        let on = self.at.is_some_and(|(x, y)| hit(x, y));
        let began_on = self.began.is_some_and(|(x, y)| hit(x, y));
        State { hovered: on && !self.touch, pressed: on && began_on, ..State::default() }
    }
}
