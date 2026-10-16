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

//! The two widgets the shared shape fits less well: a separator, which takes
//! no state, and a scroll bar, which has no height of its own to be read in.

use nonos_toolkit::widgets::{Rect, Scrollbar, Separator, State, Surface};

use super::boxes::boxed;
use super::widget::Widget;

impl Widget for Scrollbar {
    fn with(self, s: State) -> Self {
        self.state(s)
    }
    fn pref(&self) -> (u32, u32) {
        self.size()
    }
    fn paint(&self, fb: &mut impl Surface, at: Rect) {
        self.draw(fb, at)
    }
    fn read_box(&self) -> Rect {
        boxed(self.size().0, 160)
    }
}

impl Widget for Separator {
    fn with(self, _: State) -> Self {
        self
    }
    fn pref(&self) -> (u32, u32) {
        self.size()
    }
    fn paint(&self, fb: &mut impl Surface, at: Rect) {
        self.draw(fb, at)
    }
}
