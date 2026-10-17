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

//! Where a menu's panel, shadow and rows sit in `at`, which draw and hit
//! share.

use alloc::vec::Vec;

use super::row::Line;
use super::Menu;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_RADIUS, SPACE};
use crate::widgets::rect::inset;

/// The placed parts of a menu, in drawing pixels. `lines` holds one line per
/// item that fits, in item order, so the rows past the bottom are left out.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) shadow: Rect,
    pub(super) radius: u32,
    pub(super) row_radius: u32,
    pub(super) lines: Vec<Line>,
}

impl Menu<'_> {
    /// The panel fills `at` but the bottom rows the shadow drops into, and
    /// the shadow is the panel moved down by its drop. The rows stack from
    /// `SPACE.xs` inside the panel, each rounded `SPACE.xs` less than it, and
    /// a row that would cross the bottom padding is left out with those
    /// after it.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let sp = |d: u16| s.px(u32::from(d));
        let drop = Self::drop().min(at.h);
        let body = Rect { h: at.h - drop, ..at };
        let shadow = Rect { y: at.y.saturating_add(drop), ..body };
        let radius = s.px(CONTROL_RADIUS).min(body.h / 2).min(body.w / 2);
        let inner = inset(body, sp(SPACE.xs));
        let (bottom, mut y, mut lines) = (inner.y.saturating_add(inner.h), inner.y, Vec::new());
        let widest_keys = self.widest().1;
        for item in self.items {
            let h = Self::row_h(item);
            if y.saturating_add(h) > bottom {
                break;
            }
            lines.push(self.line(Rect { y, h, ..inner }, item, widest_keys));
            y = y.saturating_add(h);
        }
        Parts { body, shadow, radius, row_radius: radius.saturating_sub(sp(SPACE.xs)), lines }
    }
}
