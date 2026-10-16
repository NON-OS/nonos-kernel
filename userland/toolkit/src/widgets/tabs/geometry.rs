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

//! Where each tab and its label sit, which draw and hit share.

use alloc::vec::Vec;

use super::Tabs;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_RADIUS, SPACE, TABS_H};
use crate::widgets::text;

/// One placed tab: its rounded body and the box its label is centred in.
pub(super) struct Tab {
    pub(super) body: Rect,
    pub(super) label: Rect,
}

/// The placed tabs of a strip, in drawing pixels, in label order.
pub(super) struct Parts {
    pub(super) tabs: Vec<Tab>,
    pub(super) radius: u32,
    pub(super) label_top: i32,
    pub(super) px: f32,
}

impl Tabs<'_> {
    /// The tabs laid left to right from `at`'s left edge, `TABS_H` tall and
    /// centred vertically in `at`. When the natural widths overflow `at`,
    /// every tab gives up the same share of the overflow; anything still
    /// past the right edge is clipped there, so nothing lies outside `at`.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let (pad, gap, px) = (s.px(u32::from(SPACE.md)), s.px(u32::from(SPACE.xs)), Self::px());
        let h = s.px(TABS_H).min(at.h);
        let y = at.y.saturating_add((at.h - h) / 2);
        let widths = self.widths();
        let n = u32::try_from(widths.len().max(1)).unwrap_or(u32::MAX);
        let cut = self.span(&widths).saturating_sub(at.w).div_ceil(n);
        let right = at.x.saturating_add(at.w);
        let mut x = at.x;
        let mut place = |w: &u32| {
            let left = x.min(right);
            let body = Rect { x: left, y, w: w.saturating_sub(cut).min(right - left), h };
            x = left.saturating_add(body.w).saturating_add(gap);
            let inner = body.w.saturating_sub(pad.saturating_mul(2));
            Tab { body, label: Rect { x: left.saturating_add(pad), w: inner, ..body } }
        };
        Parts {
            tabs: widths.iter().map(&mut place).collect(),
            radius: s.px(CONTROL_RADIUS),
            label_top: text::centre_top(y, h, px),
            px,
        }
    }
}
