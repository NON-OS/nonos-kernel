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

//! Where an icon button's body, icon and label sit, which draw and hit share.

use super::IconButton;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_H, ICON, SPACE};
use crate::design::text_role::TextRole;
use crate::widgets::rect::{centre, split_left};
use crate::widgets::text;

/// The placed parts of an icon button, in drawing pixels.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) icon: Rect,
    pub(super) label: Rect,
    pub(super) label_top: i32,
    pub(super) px: f32,
}

impl IconButton<'_> {
    /// A `CONTROL_H` square with no label. With one, `SPACE.md`, the `ICON`
    /// square, `SPACE.sm`, the label's width and `SPACE.lg`, by `CONTROL_H`.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        let (h, px) = (s.px(CONTROL_H), s.font(TextRole::Body.px()));
        if self.label.is_empty() {
            return (h, h);
        }
        let room = [SPACE.md, SPACE.sm, SPACE.lg].map(|d| s.px(u32::from(d)));
        let w = room.iter().fold(s.px(ICON), |w, d| w.saturating_add(*d));
        (w.saturating_add(text::width(self.label, px)), h)
    }

    /// The body is `at` as given. With no label the icon is an `ICON` square
    /// centred in it. With one, the icon and label sit as `size` lays them
    /// out, centred across any spare width, the icon centred vertically. The
    /// icon shrinks to stay square in a body too small for it.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let (side, px) = (s.px(ICON).min(at.h).min(at.w), s.font(TextRole::Body.px()));
        let label_top = text::centre_top(at.y, at.h, px);
        if self.label.is_empty() {
            let icon = centre(at, side, side);
            return Parts { body: at, icon, label: Rect { w: 0, ..icon }, label_top, px };
        }
        let [lead, gap, tail] = [SPACE.md, SPACE.sm, SPACE.lg].map(|d| s.px(u32::from(d)));
        let spare = at.w.saturating_sub(self.size().0) / 2;
        let (_, inner) = split_left(at, lead.saturating_add(spare));
        let (slot, after) = split_left(inner, side);
        let icon = centre(slot, side.min(slot.w), side.min(slot.w));
        let (_, label) = split_left(after, gap);
        let label = Rect { w: label.w.saturating_sub(tail.saturating_add(spare)), ..label };
        Parts { body: at, icon, label, label_top, px }
    }
}
