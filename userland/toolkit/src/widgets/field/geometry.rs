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

//! Where a field's body, text and caret sit, and which part of its text is
//! shown, which draw and hit share.

use alloc::string::String;

use super::Field;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_H, CONTROL_RADIUS, FIELD_W, SPACE};
use crate::design::text_role::TextRole;
use crate::font::ttf::line_height;
use crate::widgets::text;

/// The placed parts of a field, in drawing pixels.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) radius: u32,
    pub(super) text: Rect,
    pub(super) top: i32,
    pub(super) px: f32,
    pub(super) shown: String,
    pub(super) caret: Option<Rect>,
}

impl Field<'_> {
    /// `FIELD_W` by `CONTROL_H`.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        (s.px(FIELD_W), s.px(CONTROL_H))
    }

    /// The body is `at` as given; the text box is the body less `SPACE.md`
    /// each side, with one body line centred vertically. The caret is a
    /// hairline the height of the line box, at the end of the shown text up
    /// to the caret, kept inside the text box.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let (pad, px) = (s.px(u32::from(SPACE.md)), s.font(TextRole::Body.px()));
        let room = Rect {
            x: at.x.saturating_add(pad),
            w: at.w.saturating_sub(pad.saturating_mul(2)),
            ..at
        };
        let top = text::centre_top(at.y, at.h, px);
        let (shown, k) = self.shown(room.w, px);
        let caret = k.map(|k| {
            let far = room.w.saturating_sub(s.hair());
            let dx = text::width(shown.get(..k).unwrap_or(""), px).min(far);
            Rect {
                x: room.x.saturating_add(dx),
                y: u32::try_from(top).unwrap_or(at.y),
                w: s.hair(),
                h: (line_height(px).max(0) as u32).min(at.h),
            }
        });
        Parts { body: at, radius: s.px(CONTROL_RADIUS), text: room, top, px, shown, caret }
    }
}
