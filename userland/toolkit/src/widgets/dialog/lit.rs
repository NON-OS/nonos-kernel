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

//! Which button is focused, hovered and held, and the `Button` each is drawn
//! as.

use super::Dialog;
use crate::decorations::Rect;
use crate::widgets::{Button, Pointer, State};

impl<'a> Dialog<'a> {
    /// The button the keyboard is on, which draws `focused`. An index past
    /// the last button rings none.
    pub fn focus(mut self, index: usize) -> Self {
        self.focus = Some(index);
        self
    }

    /// The button under the pointer, which draws `hovered`.
    pub fn hovered(mut self, index: Option<usize>) -> Self {
        self.hovered = index;
        self
    }

    /// The button held down, which draws `pressed`.
    pub fn pressed(mut self, index: Option<usize>) -> Self {
        self.pressed = index;
        self
    }

    /// The hovered and held buttons as `pointer` gives them for the dialog
    /// drawn at `at`: each button takes `Pointer::state` over a hit test
    /// that names it, so a press dragged off one button holds none.
    pub fn pointer(self, pointer: &Pointer, at: Rect) -> Self {
        let each = |i: usize| pointer.state(|x, y| self.hit(at, x, y) == Some(i));
        let lit = |f: fn(&State) -> bool| (0..self.buttons.len()).find(|&i| f(&each(i)));
        self.hovered(lit(|s| s.hovered)).pressed(lit(|s| s.pressed))
    }

    /// The state the app reports for the whole dialog. Only `disabled` is
    /// read: it draws the text and every button in `disabled`, and nothing
    /// is hit. Hover, press and focus belong to one button, so they come
    /// from `hovered`, `pressed` and `focus`.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }

    /// Button `i` as it is drawn: its label and kind, focused, hovered and
    /// held as set, and disabled with the dialog. `None` past the last.
    pub(super) fn button(&self, i: usize) -> Option<Button<'a>> {
        let &(label, kind) = self.buttons.get(i)?;
        let on = |set: Option<usize>| set == Some(i);
        let (focused, hovered, pressed) = (on(self.focus), on(self.hovered), on(self.pressed));
        let disabled = self.state.disabled;
        let state = State { focused, hovered, pressed, disabled, selected: false };
        Some(Button::new(label).kind(kind).state(state))
    }
}
