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

//! Painting a table, from `parts`.

use super::Table;
use crate::decorations::Rect;
use crate::theme::roles;
use crate::widgets::{draw, Surface};

impl Table<'_> {
    /// Paints the header, then the body in `inset` with every row whose
    /// whole-list index is odd striped in `surface`. The pressed row's ground
    /// takes the held fill, the selected row an `accent_wash` and the
    /// hovered row a `hover_wash` over that. Cells are in `text`, each cut
    /// with `…` to its column. A disabled table draws its inks in `disabled`
    /// and lights no row.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r) = (self.parts(at), roles());
        self.head(fb, &p);
        draw::fill(fb, p.body, r.inset);
        for (k, (row, cells)) in p.rows.iter().zip(self.rows).enumerate() {
            let i = self.first.saturating_add(k);
            let ground = if i % 2 == 1 { r.surface } else { r.inset };
            let held = self.is(self.pressed, i);
            draw::fill(fb, *row, if held { draw::pressed(ground, r.text) } else { ground });
            if self.is(self.selected, i) {
                draw::blend(fb, *row, r.accent_wash);
            }
            if self.is(self.hovered, i) {
                draw::blend(fb, *row, r.hover_wash);
            }
            let ink = self.ink(r.text);
            for ((span, col), cell) in p.cols.iter().zip(self.cols).zip(cells.iter()) {
                Self::put(fb, *span, *row, cell, col.right, ink);
            }
        }
    }
}
