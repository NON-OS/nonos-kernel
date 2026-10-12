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

use super::tabs_geom::{close_rect, plus_rect, tab_rect, Strip};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabHit {
    Tab(usize),
    Close(usize),
    Plus,
}

/// What `(x, y)` lands on; a tab's close button wins over the tab.
pub fn hit(s: &Strip, x: i32, y: i32) -> Option<TabHit> {
    for i in 0..s.n {
        let Some(r) = tab_rect(s, i) else { continue };
        if close_rect(r).contains(x, y) {
            return Some(TabHit::Close(i));
        }
        if r.contains(x, y) {
            return Some(TabHit::Tab(i));
        }
    }
    plus_rect(s).contains(x, y).then_some(TabHit::Plus)
}
