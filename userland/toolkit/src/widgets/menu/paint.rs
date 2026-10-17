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

//! Painting and hit testing a menu, both from `parts`.

use super::Menu;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::theme::{roles, Opaque};
use crate::widgets::checkbox::tick::along;
use crate::widgets::rect::contains;
use crate::widgets::{draw, text, Surface};

impl Menu<'_> {
    /// Paints the `shadow` under the panel, the opaque `raised` panel over it
    /// with a `border` hairline, then each row: a separator as a
    /// `border_soft` hairline, any other item with its tick and label in
    /// `text` and its shortcut in `muted`. The pressed row takes the held
    /// fill and the hovered row a `hover_wash`. A disabled item, or every
    /// item in a disabled menu, is drawn in `disabled` with neither.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s, px) = (self.parts(at), roles(), scale(), Self::px());
        draw::round(fb, p.shadow, p.radius, r.shadow);
        draw::round(fb, p.body, p.radius, r.raised);
        draw::outline(fb, p.body, p.radius, s.hair(), r.border);
        for (i, (line, item)) in p.lines.iter().zip(self.items).enumerate() {
            if item.separator {
                draw::round(fb, line.rule, 0, r.border_soft);
                continue;
            }
            let live = item.live() && !self.state.disabled;
            if live && self.pressed == Some(i) {
                draw::round(fb, line.row, p.row_radius, draw::pressed(r.raised, r.text));
            }
            if live && self.hovered == Some(i) {
                draw::round(fb, line.row, p.row_radius, r.hover_wash);
            }
            let ink = |c: Opaque| if live { c } else { r.disabled };
            if item.check == Some(true) {
                let dots = line.tick.windows(2).flat_map(|arm| along(arm[0], arm[1]));
                dots.for_each(|(x, y)| draw::dot(fb, x, y, line.stroke, ink(r.text)));
            }
            let label = text::truncate(item.label, line.label.w, px);
            text::left(fb, line.label.x, line.top, &label, ink(r.text), px);
            let keys = text::truncate(item.shortcut, line.keys.w, px);
            let right = line.keys.x.saturating_add(line.keys.w);
            text::right(fb, right, line.top, &keys, ink(r.muted), px);
        }
    }

    /// The index of the item under the point, if any. A separator, a
    /// disabled item, the padding round the rows and every point of a
    /// disabled menu give `None`. `at` and the point use `draw`'s
    /// coordinates: content coordinates when drawn through `Scrolled`, so
    /// pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> Option<usize> {
        let lines = self.parts(at).lines;
        let i = lines.iter().position(|line| contains(line.row, x, y))?;
        (self.items[i].live() && !self.state.disabled).then_some(i)
    }
}
