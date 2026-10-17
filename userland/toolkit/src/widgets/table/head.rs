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

//! Painting a table's header: its band, its titles and the sort chevron.

use super::geometry::{Parts, Span};
use super::Table;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{SORT_MARK, SPACE};
use crate::theme::{roles, Opaque};
use crate::widgets::{draw, Surface};

impl Table<'_> {
    /// Paints the header band in `sunken` with a `border` hairline under
    /// it, and, when the band has its full height, each title in `muted`.
    /// The sorted column's title is in `accent_text`, with a chevron after
    /// it, or before it in a right-hand column, `SPACE.xs` away. A column too
    /// narrow for the chevron shows its title alone.
    pub(super) fn head(&self, fb: &mut impl Surface, p: &Parts) {
        let (r, s) = (roles(), scale());
        draw::fill(fb, p.head, r.sunken);
        draw::fill(fb, p.rule, r.border);
        if !p.titled {
            return;
        }
        let (m, gap) = (s.px(SORT_MARK), s.px(u32::from(SPACE.xs)));
        let room = m.saturating_add(gap);
        for (c, (span, col)) in p.cols.iter().zip(self.cols).enumerate() {
            let order = self.sort.filter(|(at, _)| *at == c && span.ink_w >= room);
            let Some((_, up)) = order else {
                Self::put(fb, *span, p.head, col.title, col.right, self.ink(r.muted));
                continue;
            };
            let ink = self.ink(r.accent_text);
            let ink_x = span.ink_x.saturating_add(if col.right { room } else { 0 });
            let short = Span { ink_x, ink_w: span.ink_w - room, ..*span };
            let (x, w) = Self::put(fb, short, p.head, col.title, col.right, ink);
            let x = if col.right { x - room } else { x.saturating_add(w + gap) };
            chevron(fb, Rect { x, w: m, ..p.head }, up, ink);
        }
    }
}

/// Fills a chevron as wide as `at`, centred down it, pointing up when `up`
/// and down otherwise: two strokes a double hairline thick, stepped a pixel
/// at a time, meeting at the middle.
fn chevron(fb: &mut impl Surface, at: Rect, up: bool, ink: Opaque) {
    let t = scale().hair().saturating_mul(2).min(at.w);
    let reach = (at.w - t) / 2;
    let x0 = at.x.saturating_add((at.w - reach * 2 - t) / 2);
    let y0 = at.y.saturating_add(at.h.saturating_sub(reach + t) / 2);
    for k in 0..=reach {
        let y = y0.saturating_add(if up { reach - k } else { k });
        for x in [x0.saturating_add(k), x0.saturating_add(reach * 2 - k)] {
            draw::fill(fb, Rect { x, y, w: t, h: t }, ink);
        }
    }
}
