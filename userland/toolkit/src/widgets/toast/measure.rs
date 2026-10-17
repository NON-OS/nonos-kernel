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

//! A toast's size, and how its width divides between text and action.

use super::Toast;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_H, LINE_GAP, SPACE, TOAST_W};
use crate::design::text_role::TextRole;
use crate::font::ttf::line_height;
use crate::widgets::text;

impl Toast<'_> {
    /// `SPACE.sm` each side, the bar, `SPACE.md`, the text on one line and
    /// the action's room, capped at `TOAST_W`. By the text's lines at that
    /// width, at most two, or `CONTROL_H` with an action if that is taller,
    /// plus `SPACE.sm` above and below and the drop of the shadow.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        let sp = |d: u16| s.px(u32::from(d));
        let edges = sp(SPACE.sm).saturating_mul(2).saturating_add(sp(SPACE.xs) + sp(SPACE.md));
        let button = sp(SPACE.md).saturating_add(self.button().size().0);
        let tail = if self.action.is_empty() { sp(SPACE.xs) } else { button };
        let w = edges.saturating_add(text::width(self.text, Self::px())).saturating_add(tail);
        let w = w.min(s.px(TOAST_W));
        let n = self.lines(self.across(w.saturating_sub(edges)).0, 2).len().max(1) as u32;
        let lh = line_height(Self::px()).max(0) as u32;
        let text_h = n * lh + (n - 1) * s.px(LINE_GAP);
        let control = if self.action.is_empty() { 0 } else { s.px(CONTROL_H) };
        let pads = sp(SPACE.sm).saturating_mul(2).saturating_add(Self::drop());
        (w, text_h.max(control).saturating_add(pads))
    }

    /// The body text size the text and action are drawn at.
    pub(super) fn px() -> f32 {
        scale().font(TextRole::Body.px())
    }

    /// How far the shadow drops below the panel: two hairlines.
    pub(super) fn drop() -> u32 {
        scale().hair().saturating_mul(2)
    }

    /// `w`, the width after the bar and its gap, split into the text's room
    /// and the action's width. With no action the text stops `SPACE.xs`
    /// short. With one, the action follows a `SPACE.md` gap at its button's
    /// width, but leaves the text its own width or half the room, if less.
    pub(super) fn across(&self, w: u32) -> (u32, u32) {
        let sp = |d: u16| scale().px(u32::from(d));
        if self.action.is_empty() {
            return (w.saturating_sub(sp(SPACE.xs)), 0);
        }
        let w = w.saturating_sub(sp(SPACE.md));
        let keep = text::width(self.text, Self::px()).min(w / 2);
        let button = self.button().size().0.min(w - keep);
        (w - button, button)
    }
}
