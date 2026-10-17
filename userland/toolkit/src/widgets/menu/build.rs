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

//! The menu and the builders that set it up.

use super::Item;
use crate::widgets::State;

/// A raised panel of rows, one per item, drawn over what the window holds.
#[derive(Clone, Copy, Debug)]
pub struct Menu<'a> {
    pub(super) items: &'a [Item<'a>],
    pub(super) hovered: Option<usize>,
    pub(super) pressed: Option<usize>,
    pub(super) width: Option<u32>,
    pub(super) state: State,
}

impl<'a> Menu<'a> {
    /// A menu of `items`, top to bottom, with no row lit, as wide as its
    /// widest row.
    pub fn new(items: &'a [Item<'a>]) -> Self {
        Menu { items, hovered: None, pressed: None, width: None, state: State::default() }
    }

    /// The row under the pointer, or the one the arrow keys have reached. It
    /// gets a hover wash unless it is a separator or disabled.
    pub fn hovered(mut self, index: Option<usize>) -> Self {
        self.hovered = index;
        self
    }

    /// The row held down. It takes the held fill unless it is a separator or
    /// disabled.
    pub fn pressed(mut self, index: Option<usize>) -> Self {
        self.pressed = index;
        self
    }

    /// The width to draw at, in drawing pixels, in place of the measured
    /// one, such as the width of the field a list opens from.
    pub fn width(mut self, w: u32) -> Self {
        self.width = Some(w);
        self
    }

    /// The state the app reports for the whole menu. Only `disabled` is
    /// read: it draws every row in `disabled`, with no wash, and nothing is
    /// hit. Hover and press belong to one row, so they come from `hovered`
    /// and `pressed`.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}
