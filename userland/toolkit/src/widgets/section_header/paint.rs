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

//! Measuring and painting a section header, both from `lines`.

use super::SectionHeader;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::LINE_GAP;
use crate::design::text_role::TextRole;
use crate::font::ttf::line_height;
use crate::paint::PaintBuffer;
use crate::theme::roles;
use crate::widgets::text;

/// The placed lines of a section header, in drawing pixels.
struct Lines {
    title_px: f32,
    note_px: f32,
    title_top: i32,
    note_top: i32,
    h: u32,
}

impl SectionHeader<'_> {
    /// The width of the title and the height of the stacked lines.
    pub fn size(&self) -> (u32, u32) {
        let l = self.lines(Rect { x: 0, y: 0, w: 0, h: 0 });
        (text::width(self.title, l.title_px), l.h)
    }

    /// Paints the lines left-aligned at `at.x`, stacked and centred down
    /// `at`, each cut with an ellipsis to `at.w`.
    pub fn draw(&self, fb: &mut PaintBuffer, at: Rect) {
        let (l, r) = (self.lines(at), roles());
        let off = self.state.disabled;
        let (ink, note_ink) = if off { (r.disabled, r.disabled) } else { (r.text, r.muted) };
        let title = text::truncate(self.title, at.w, l.title_px);
        text::left(fb, at.x, l.title_top, &title, ink, l.title_px);
        if let Some(note) = self.note {
            let line = text::truncate(note, at.w, l.note_px);
            text::left(fb, at.x, l.note_top, &line, note_ink, l.note_px);
        }
    }

    /// The text sizes, the tops of both lines and their stacked height.
    fn lines(&self, at: Rect) -> Lines {
        let s = scale();
        let (title_px, note_px) = (s.font(TextRole::Title.px()), s.font(TextRole::Body.px()));
        let title_lh = line_height(title_px).max(0) as u32;
        let note_h = (line_height(note_px).max(0) as u32).saturating_add(s.px(LINE_GAP));
        let h = title_lh.saturating_add(if self.note.is_some() { note_h } else { 0 });
        let title_y = at.y.saturating_add(at.h.saturating_sub(h) / 2);
        let top = |y: u32| i32::try_from(y).unwrap_or(i32::MAX);
        let note_top = top(title_y.saturating_add(title_lh).saturating_add(s.px(LINE_GAP)));
        Lines { title_px, note_px, title_top: top(title_y), note_top, h }
    }
}
