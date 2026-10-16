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

//! Where a button's body and label sit, which draw and hit share.

use super::Button;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_H, CONTROL_RADIUS, SPACE};
use crate::design::text_role::TextRole;
use crate::widgets::text;

/// The placed parts of a button, in drawing pixels.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) radius: u32,
    pub(super) label: Rect,
    pub(super) label_top: i32,
    pub(super) px: f32,
}

impl Button<'_> {
    /// The label's width plus `SPACE.lg` each side, by `CONTROL_H`.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        let pad = s.px(u32::from(SPACE.lg)).saturating_mul(2);
        (text::width(self.label, Self::px()).saturating_add(pad), s.px(CONTROL_H))
    }

    /// The body text size the label is drawn at.
    fn px() -> f32 {
        scale().font(TextRole::Body.px())
    }

    /// The body is `at` as given, so an app may make a button wider than its
    /// size; the label box is the body less `SPACE.lg` each side, with the
    /// line centred vertically in the body.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let pad = s.px(u32::from(SPACE.lg));
        let px = Self::px();
        let label = Rect {
            x: at.x.saturating_add(pad),
            w: at.w.saturating_sub(pad.saturating_mul(2)),
            ..at
        };
        Parts {
            body: at,
            radius: s.px(CONTROL_RADIUS),
            label,
            label_top: text::centre_top(at.y, at.h, px),
            px,
        }
    }
}
