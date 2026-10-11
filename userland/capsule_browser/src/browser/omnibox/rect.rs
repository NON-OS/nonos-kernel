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

use crate::browser::ui::rect::Rect as Area;

/* A screen rectangle in content-area pixels. */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub fn union(self, o: Rect) -> Rect {
        let (x, y) = (self.x.min(o.x), self.y.min(o.y));
        let r = (self.x + self.w).max(o.x + o.w);
        let b = (self.y + self.h).max(o.y + o.h);
        Rect { x, y, w: r - x, h: b - y }
    }

    /* This rect, given relative to `origin`, moved to where `origin` is. */
    pub fn within(self, origin: Rect) -> Rect {
        Rect { x: origin.x.saturating_add(self.x), y: origin.y.saturating_add(self.y), ..self }
    }
}

/* A layout rect, its negative extents taken as zero. */
impl From<Area> for Rect {
    fn from(r: Area) -> Rect {
        let at = |v: i32| v.max(0) as u32;
        Rect { x: at(r.x), y: at(r.y), w: at(r.w), h: at(r.h) }
    }
}
