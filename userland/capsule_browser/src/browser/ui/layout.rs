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

use super::limits::TOOLBAR_H;
use super::rect::Rect;

/// How much room the sidebar takes. Hidden is the only mode until the
/// sidebar has a painter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidebarMode {
    Hidden,
}

/// Where the toolbar, sidebar and page content sit inside the window surface.
/// Every painter and every hit-test reads the same value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    pub toolbar: Rect,
    pub sidebar: Rect,
    pub content: Rect,
}

/// Split a `w` x `h` surface: toolbar across the top, sidebar down the left
/// below it, page content in the rest. Negative sizes count as zero.
pub fn compute(w: i32, h: i32, mode: SidebarMode) -> Layout {
    let w = w.max(0);
    let h = h.max(0);
    let bar = TOOLBAR_H.min(h);
    let side = sidebar_w(mode);
    let below = h - bar;
    Layout {
        toolbar: Rect::new(0, 0, w, bar),
        sidebar: Rect::new(0, bar, side, below),
        content: Rect::new(side, bar, w - side, below),
    }
}

fn sidebar_w(mode: SidebarMode) -> i32 {
    match mode {
        SidebarMode::Hidden => 0,
    }
}
