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

//! Where a navigation item's body, icon and label sit, which draw and hit
//! share.

use super::NavItem;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_RADIUS, ICON, NAV_H, SPACE};
use crate::design::text_role::TextRole;
use crate::widgets::rect::{centre, split_left};
use crate::widgets::text;

/// The placed parts of a navigation item, in drawing pixels.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) radius: u32,
    pub(super) icon: Option<Rect>,
    pub(super) label: Rect,
    pub(super) label_top: i32,
    pub(super) px: f32,
}

impl NavItem<'_> {
    /// The label's width plus `SPACE.md` each side, and any `ICON` square
    /// with `SPACE.md` after it, by `NAV_H`. An item fills the width it is
    /// given, so this is only the least it wants.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        let pad = s.px(u32::from(SPACE.md));
        let icon = self.icon.map_or(0, |_| s.px(ICON).saturating_add(pad));
        let w = text::width(self.label, Self::px()).saturating_add(pad.saturating_mul(2));
        (w.saturating_add(icon), s.px(NAV_H))
    }

    /// The body text size the label is drawn at.
    fn px() -> f32 {
        scale().font(TextRole::Body.px())
    }

    /// The body is `at` as given. Any icon is an `ICON` square `SPACE.md` in
    /// from the left, centred vertically. The label box runs from `SPACE.md`
    /// after the icon, or `SPACE.md` in without one, to `SPACE.md` short of
    /// the right edge, with the line centred vertically in the body.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let (pad, side, px) = (s.px(u32::from(SPACE.md)), s.px(ICON).min(at.h), Self::px());
        let (_, inner) = split_left(at, pad);
        let (slot, after) = split_left(inner, self.icon.map_or(0, |_| side));
        let icon = self.icon.map(|_| centre(slot, side, side));
        let (_, label) = split_left(after, icon.map_or(0, |_| pad));
        let label = Rect { w: label.w.saturating_sub(pad), ..label };
        let label_top = text::centre_top(at.y, at.h, px);
        Parts { body: at, radius: s.px(CONTROL_RADIUS), icon, label, label_top, px }
    }
}
