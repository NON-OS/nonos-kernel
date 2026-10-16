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

//! Where a scroll bar's thumb sits, which draw and hit share.

use super::Scrollbar;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{SCROLL_MIN, SCROLL_W};
use crate::widgets::rect::share;

/// The placed thumb, in drawing pixels. Its top travels `travel` pixels
/// down as the offset goes from 0 to `most`.
pub(super) struct Parts {
    pub(super) thumb: Rect,
    pub(super) radius: u32,
    pub(super) travel: u32,
    pub(super) most: u32,
}

impl Scrollbar {
    /// `SCROLL_W` wide, with no height of its own, since a bar runs the
    /// height it is given.
    pub fn size(&self) -> (u32, u32) {
        (scale().px(SCROLL_W), 0)
    }

    /// None when the content fits the viewport. Otherwise the thumb,
    /// `SCROLL_W` wide at the right of `at`, its height the viewport's share
    /// of `at.h` but no less than `SCROLL_MIN` and no more than `at.h`, its
    /// top `offset / most` of the way from `at.y` to `at.y + at.h - h`.
    pub(super) fn parts(&self, at: Rect) -> Option<Parts> {
        if self.content <= self.viewport {
            return None;
        }
        let s = scale();
        let most = self.content - self.viewport;
        let w = s.px(SCROLL_W).min(at.w);
        let h = share(self.viewport, at.h, self.content).max(s.px(SCROLL_MIN)).min(at.h);
        let travel = at.h - h;
        let y = at.y.saturating_add(share(self.offset.min(most), travel, most));
        let thumb = Rect { x: at.x.saturating_add(at.w - w), y, w, h };
        Some(Parts { thumb, radius: w / 2, travel, most })
    }
}
