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

//! Painting and hit testing a toast, both from `parts`, and the lines its
//! text takes.

use alloc::string::String;
use alloc::vec::Vec;

use super::Toast;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::theme::roles;
use crate::widgets::rect::contains;
use crate::widgets::{draw, text, Surface};

impl Toast<'_> {
    /// Paints the `shadow` under the panel, the opaque `raised` panel over
    /// it with a `border` hairline, the bar in the tone's colour, the lines
    /// in `text`, then the action as its `Plain` `Button` draws it in the
    /// toast's state. Disabled draws the bar and lines in `disabled`.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s) = (self.parts(at), roles(), scale());
        draw::round(fb, p.shadow, p.radius, r.shadow);
        draw::round(fb, p.body, p.radius, r.raised);
        draw::outline(fb, p.body, p.radius, s.hair(), r.border);
        let live = !self.state.disabled;
        let ink = |c| if live { c } else { r.disabled };
        draw::round(fb, p.bar, p.bar.w / 2, ink(self.tone.colour(&r)));
        for (i, line) in p.lines.iter().enumerate() {
            let top = p.room.y.saturating_add(p.step.saturating_mul(i as u32));
            let top = i32::try_from(top).unwrap_or(i32::MAX);
            text::left(fb, p.room.x, top, line, ink(r.text), Self::px());
        }
        if let Some(a) = p.action {
            self.button().draw(fb, a);
        }
    }

    /// Whether the point lies on the action button; false with no action.
    /// `at` and the point use `draw`'s coordinates: content coordinates when
    /// drawn through `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        self.parts(at).action.is_some_and(|a| contains(a, x, y))
    }

    /// The lines the text wraps to in `w`, at most `most`, each cut with `…`
    /// to fit. The last takes the rest of the text, so it is cut when more
    /// would follow.
    pub(super) fn lines(&self, w: u32, most: usize) -> Vec<String> {
        let (t, px) = (self.text, Self::px());
        let spans = text::wrap(t, w, px).into_iter().take(most).enumerate();
        let end = |i: usize, e: usize| if i + 1 == most { t.len() } else { e };
        spans.map(|(i, (s, e))| text::truncate(t[s..end(i, e)].trim_end(), w, px)).collect()
    }
}
