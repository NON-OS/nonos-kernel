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

//! A pill's natural size, which its size and its layout share.

use super::Pill;
use crate::design::scale::scale;
use crate::design::size::{DOT, PILL_H, PILL_PAD, SPACE};
use crate::design::text_role::TextRole;
use crate::widgets::text;

impl Pill<'_> {
    /// The label's width plus `PILL_PAD` each side, plus the dot and a
    /// `SPACE.xs` gap when there is one, by `PILL_H`.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        let pad = s.px(PILL_PAD).saturating_mul(2);
        let w = text::width(self.label, Self::px()).saturating_add(pad);
        (w.saturating_add(self.lead()), s.px(PILL_H))
    }

    /// The body text size the label is drawn at.
    pub(super) fn px() -> f32 {
        scale().font(TextRole::Body.px())
    }

    /// The width the dot and its gap take before the label; 0 with no dot.
    pub(super) fn lead(&self) -> u32 {
        if !self.dot {
            return 0;
        }
        let s = scale();
        s.px(DOT).saturating_add(s.px(u32::from(SPACE.xs)))
    }
}
