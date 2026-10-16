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

//! Measuring, placing content in, painting and hit testing a card, all from
//! `parts`.

use super::Card;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::CARD_RADIUS;
use crate::paint::PaintBuffer;
use crate::theme::derive::mix;
use crate::theme::{roles, Opaque};
use crate::widgets::rect::contains;
use crate::widgets::{draw, text};

impl Card<'_> {
    /// No width of its own and the head height: a card fills the Rect it is
    /// given, and an app makes it as tall as its content needs.
    pub fn size(&self) -> (u32, u32) {
        (0, self.head_h())
    }

    /// The area below the head, inset by `SPACE.lg` on the left, right and
    /// bottom, where an app places the card's rows.
    pub fn content(&self, at: Rect) -> Rect {
        self.parts(at).content
    }

    /// Paints the body, its outline, the state washes and the head text.
    pub fn draw(&self, fb: &mut PaintBuffer, at: Rect) {
        let (p, r, s, st) = (self.parts(at), roles(), scale(), self.state);
        let (radius, hair, live) = (s.px(CARD_RADIUS), s.hair(), !st.disabled);
        let pressed = Opaque::new(mix(r.surface.argb(), r.bg.argb(), 32));
        let fill = if live && st.pressed { pressed } else { r.surface };
        draw::round(fb, p.body, radius, fill);
        if live && st.hovered {
            draw::round(fb, p.body, radius, r.hover_wash);
        }
        if live && st.selected {
            draw::outline(fb, p.body, radius, hair, r.accent_edge);
        } else {
            draw::outline(fb, p.body, radius, hair, r.border);
        }
        if live && st.focused {
            draw::outline(fb, p.body, radius, hair.saturating_mul(2), r.focus_ring);
        }
        let Some(title) = self.title else { return };
        let (ink, note_ink) = if live { (r.text, r.muted) } else { (r.disabled, r.disabled) };
        text::left(fb, p.text.x, p.title_top, &text::truncate(title, p.text.w, p.px), ink, p.px);
        if let Some(note) = self.note {
            let line = text::truncate(note, p.text.w, p.px);
            text::left(fb, p.text.x, p.note_top, &line, note_ink, p.px);
        }
    }

    /// Whether the point lies on the card.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        contains(self.parts(at).body, x, y)
    }
}
