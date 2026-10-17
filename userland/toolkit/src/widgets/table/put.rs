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

//! The ink a table draws in and the text of one cell.

use super::geometry::Span;
use super::Table;
use crate::decorations::Rect;
use crate::theme::{roles, Opaque};
use crate::widgets::{text, Surface};

impl Table<'_> {
    /// `ink`, or `disabled` in a disabled table.
    pub(super) fn ink(&self, ink: Opaque) -> Opaque {
        if self.state.disabled {
            roles().disabled
        } else {
            ink
        }
    }

    /// Draws `s` cut with `…` to the ink part of `span`, centred down `band`,
    /// against the part's right edge when `right` and its left otherwise.
    /// Returns the x the run starts at and its width.
    pub(super) fn put(
        fb: &mut impl Surface,
        span: Span,
        band: Rect,
        s: &str,
        right: bool,
        ink: Opaque,
    ) -> (u32, u32) {
        let (px, top) = (Self::px(), text::centre_top(band.y, band.h, Self::px()));
        let cut = text::truncate(s, span.ink_w, px);
        let w = text::width(&cut, px);
        let x = if right {
            span.ink_x.saturating_add(span.ink_w.saturating_sub(w))
        } else {
            span.ink_x
        };
        text::left(fb, x, top, &cut, ink, px);
        (x, w)
    }
}
