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

//! A tooltip's size, and where its box, shadow and text sit in `at`.

use super::Tooltip;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_RADIUS, PILL_H, SPACE, TOOLTIP_MAX_W};
use crate::design::text_role::TextRole;
use crate::font::ttf::line_height;
use crate::widgets::rect::centre;
use crate::widgets::text;

/// The placed parts of a tooltip, in drawing pixels. `room` is where the text
/// may go, with no width when a line is taller than the box.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) shadow: Rect,
    pub(super) radius: u32,
    pub(super) room: Rect,
    pub(super) top: i32,
    pub(super) px: f32,
}

impl Tooltip<'_> {
    /// The text's width plus `SPACE.sm` each side, capped at `TOOLTIP_MAX_W`,
    /// by `PILL_H` plus the drop of the shadow under the box.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        let pad = s.px(u32::from(SPACE.sm)).saturating_mul(2);
        let w = text::width(self.text, s.font(TextRole::Body.px())).saturating_add(pad);
        (w.min(s.px(TOOLTIP_MAX_W)), s.px(PILL_H).saturating_add(Self::drop()))
    }

    /// How far the shadow drops below the box: two hairlines.
    fn drop() -> u32 {
        scale().hair().saturating_mul(2)
    }

    /// The tooltip's size, clamped to `at` and centred in it. The box takes
    /// all of that but the bottom rows the shadow drops into, and the shadow
    /// is the box moved down by its drop, so both stay in `at`. The text sits
    /// `SPACE.sm` in from each side, centred vertically in the box.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let (s, (w, h)) = (scale(), self.size());
        let px = s.font(TextRole::Body.px());
        let whole = centre(at, w, h);
        let drop = Self::drop().min(whole.h);
        let body = Rect { h: whole.h - drop, ..whole };
        let shadow = Rect { y: whole.y.saturating_add(drop), ..body };
        let radius = s.px(CONTROL_RADIUS).min(body.h / 2).min(body.w / 2);
        let pad = s.px(u32::from(SPACE.sm));
        let one_line = line_height(px).max(0) as u32 <= body.h;
        let w = if one_line { body.w.saturating_sub(pad.saturating_mul(2)) } else { 0 };
        let room = Rect { x: body.x.saturating_add(pad), w, ..body };
        Parts { body, shadow, radius, room, top: text::centre_top(body.y, body.h, px), px }
    }
}
