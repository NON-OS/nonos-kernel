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

//! Painting and hit testing a dialog, both from `parts`.

use super::Dialog;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::theme::{roles, Opaque};
use crate::widgets::{draw, text, Surface};

impl Dialog<'_> {
    /// Blends the `scrim` over all of `at`, then paints the `shadow` under
    /// the panel, the opaque `surface` panel over it with a `border`
    /// hairline, the title in `text`, the body's lines in `text_2`, the
    /// note in its tone's ink, and each button as its `Button` draws it.
    /// Disabled draws the text in `disabled` and every button disabled.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s) = (self.parts(at), roles(), scale());
        draw::blend(fb, at, r.scrim);
        draw::round(fb, p.shadow, p.radius, r.shadow);
        draw::round(fb, p.panel, p.radius, r.surface);
        draw::outline(fb, p.panel, p.radius, s.hair(), r.border);
        let ink = |c: Opaque| if self.state.disabled { r.disabled } else { c };
        let top = |y: u32| i32::try_from(y).unwrap_or(i32::MAX);
        if let Some(t) = p.title {
            let title = text::truncate(self.title, t.w, Self::title_px());
            text::left(fb, t.x, top(t.y), &title, ink(r.text), Self::title_px());
        }
        for (i, line) in p.lines.iter().enumerate() {
            let y = p.text.y.saturating_add(p.step.saturating_mul(i as u32));
            text::left(fb, p.text.x, top(y), line, ink(r.text_2), Self::px());
        }
        if let Some(n) = p.note {
            let note = text::truncate(self.note, n.w, Self::px());
            text::left(fb, n.x, top(n.y), &note, ink(self.tone.colour(&r)), Self::px());
        }
        for (b, at) in self.each().zip(p.buttons) {
            b.draw(fb, at);
        }
    }

    /// The index of the button under the point, if any: the button whose
    /// own `hit` takes it on the rect the dialog gives it. The panel, the
    /// text, the scrim and every point of a disabled dialog give `None`.
    /// `at` and the point use `draw`'s coordinates: content coordinates
    /// when drawn through `Scrolled`, so pass the pointer's y plus the
    /// scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> Option<usize> {
        if self.state.disabled {
            return None;
        }
        self.each().zip(self.parts(at).buttons).position(|(b, r)| b.hit(r, x, y))
    }

    /// Where the panel and its shadow sit when the dialog is drawn at `at`.
    /// The app closes the dialog, or ignores the press, when a press lands
    /// outside it.
    pub fn panel(&self, at: Rect) -> Rect {
        self.parts(at).area
    }
}
