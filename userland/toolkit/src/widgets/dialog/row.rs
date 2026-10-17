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

//! Where a dialog's buttons sit in their row, and how wide the row is.

use alloc::vec;
use alloc::vec::Vec;

use super::Dialog;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::CONTROL_H;
use crate::widgets::Button;

impl<'a> Dialog<'a> {
    /// Every button, first to last, as it is drawn.
    pub(super) fn each(&self) -> impl Iterator<Item = Button<'a>> + '_ {
        (0..self.buttons.len()).filter_map(|i| self.button(i))
    }

    /// Every button at its own width, `SPACE.sm` apart.
    pub(super) fn row_w(&self) -> u32 {
        let n = self.buttons.len() as u32;
        let sum = self.each().fold(0u32, |w, b| w.saturating_add(b.size().0));
        sum.saturating_add(Self::sm().saturating_mul(n.saturating_sub(1)))
    }

    /// Splits `inner` into the room above the buttons and the buttons'
    /// rects. The row is `CONTROL_H` tall at the bottom, `SPACE.xl` under
    /// the room, and holds each button at its own width, right-aligned.
    /// When they do not fit across, each takes an equal share and the gaps
    /// shrink to leave half the row at least. With no button, or no room
    /// for the row, the room is all of `inner` and there is no button.
    pub(super) fn row(&self, inner: Rect) -> (Rect, Vec<Rect>) {
        let ch = scale().px(CONTROL_H);
        if self.buttons.is_empty() || inner.h < ch {
            return (inner, Vec::new());
        }
        let room = Rect { h: (inner.h - ch).saturating_sub(Self::pad()), ..inner };
        let n = self.buttons.len() as u32;
        let mut widths: Vec<u32> = self.each().map(|b| b.size().0).collect();
        let mut gap = Self::sm();
        if widths.iter().sum::<u32>() + gap * (n - 1) > inner.w {
            gap = gap.min(inner.w / (2 * n));
            widths = vec![(inner.w - gap * (n - 1)) / n; n as usize];
        }
        let used = widths.iter().sum::<u32>() + gap * (n - 1);
        let mut x = inner.x.saturating_add(inner.w - used);
        let y = inner.y.saturating_add(inner.h - ch);
        let rects = widths.into_iter().map(|w| {
            let r = Rect { x, y, w, h: ch };
            x = x.saturating_add(w + gap);
            r
        });
        (room, rects.collect())
    }
}
