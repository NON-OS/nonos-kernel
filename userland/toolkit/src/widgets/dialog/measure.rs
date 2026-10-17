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

//! A dialog's size, and the measures its parts share.

use super::Dialog;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_H, DIALOG_LINES, DIALOG_W, SPACE};
use crate::design::text_role::TextRole;
use crate::widgets::text;

impl Dialog<'_> {
    /// Across: `SPACE.xl` each side of the widest of the title, the body on
    /// one line, the note and the row of buttons, capped at `DIALOG_W`.
    /// Down: `SPACE.xl` above and below everything, the title's line, the
    /// body's lines at that width, at most `DIALOG_LINES`, the note and,
    /// with any button, `SPACE.xl` and a `CONTROL_H` row, then the shadow.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        let (pad, px) = (Self::pad(), Self::px());
        let widths = [text::width(self.title, Self::title_px()), self.row_w()];
        let widths = widths.into_iter().chain([self.body, self.note].map(|t| text::width(t, px)));
        let w = widths.max().unwrap_or(0).saturating_add(pad * 2).min(s.px(DIALOG_W));
        let n = self.lines(w.saturating_sub(pad * 2), DIALOG_LINES as usize).len() as u32;
        let note = if self.note.is_empty() { 0 } else { Self::sm() + Self::lh() };
        let row = if self.buttons.is_empty() { 0 } else { pad + s.px(CONTROL_H) };
        let stack = Self::title_h() + Self::block(n) + note + row;
        (w, stack.saturating_add(pad * 2).saturating_add(Self::drop()))
    }

    /// The body text size the body, note and buttons are drawn at.
    pub(super) fn px() -> f32 {
        scale().font(TextRole::Body.px())
    }

    /// The title text size.
    pub(super) fn title_px() -> f32 {
        scale().font(TextRole::Title.px())
    }

    /// The panel's padding, `SPACE.xl`, which also parts text and buttons.
    pub(super) fn pad() -> u32 {
        scale().px(u32::from(SPACE.xl))
    }

    /// How far the shadow drops below the panel: two hairlines.
    pub(super) fn drop() -> u32 {
        scale().hair().saturating_mul(2)
    }
}
