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

//! Where the tick, label, shortcut and hairline sit in one row of a menu.

use super::{Item, Menu};
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CHECK, ICON, SPACE, TICK};
use crate::widgets::checkbox::geometry::PATH;
use crate::widgets::rect::{centre, share, split_left};
use crate::widgets::text;

/// One placed row: its body, the tick's path and the radius of the dots
/// that draw it, where its label and shortcut go, the hairline a separator
/// draws, and the top of its line of text.
pub(super) struct Line {
    pub(super) row: Rect,
    pub(super) tick: [(u32, u32); 3],
    pub(super) stroke: u32,
    pub(super) label: Rect,
    pub(super) keys: Rect,
    pub(super) rule: Rect,
    pub(super) top: i32,
}

impl Menu<'_> {
    /// The parts of `item`'s row, `row` being its body and `widest_keys` the
    /// width of the widest shortcut. Inside `SPACE.md` of the row's sides
    /// come the tick's room, its tick shaped as a checkbox's in an `ICON`
    /// square, then the label, then, for an item with keys,
    /// `SPACE.xl` and the shortcut's column, which takes at most half of what
    /// is left. A separator's hairline runs across the row's middle.
    pub(super) fn line(&self, row: Rect, item: &Item, widest_keys: u32) -> Line {
        let s = scale();
        let sp = |d: u16| s.px(u32::from(d));
        let (_, room) = split_left(row, sp(SPACE.md));
        let room = Rect { w: room.w.saturating_sub(sp(SPACE.md)), ..room };
        let (lead, rest) = split_left(room, self.lead());
        let m = centre(Rect { w: s.px(ICON).min(lead.w), ..lead }, s.px(ICON), s.px(ICON));
        let tick = PATH.map(|(x, y)| {
            (m.x.saturating_add(share(x, m.w, CHECK)), m.y.saturating_add(share(y, m.h, CHECK)))
        });
        let stroke = (share(TICK, m.w, CHECK) / 2).max(1);
        let keys_w = if item.shortcut.is_empty() { 0 } else { widest_keys.min(rest.w / 2) };
        let gap = if keys_w == 0 { 0 } else { sp(SPACE.xl).min(rest.w - keys_w) };
        let label = Rect { w: rest.w - keys_w - gap, ..rest };
        let keys = Rect { x: rest.x.saturating_add(rest.w - keys_w), w: keys_w, ..rest };
        let rule = centre(row, row.w, s.hair());
        let top = text::centre_top(row.y, row.h, Self::px());
        Line { row, tick, stroke, label, keys, rule, top }
    }
}
