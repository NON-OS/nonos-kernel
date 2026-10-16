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

//! Where a row's label, note, value and chevron sit, which draw and hit share.

use super::Row;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CHEVRON, LINE_GAP, SPACE};
use crate::widgets::rect::{centre, inset, split_left};
use crate::widgets::text;

/// The placed parts of a row, in drawing pixels.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) label: Rect,
    pub(super) label_top: i32,
    pub(super) note_top: i32,
    pub(super) value: Rect,
    pub(super) value_top: i32,
    pub(super) chevron: Rect,
    pub(super) px: f32,
}

impl Row<'_> {
    /// The body, the label column, the value box, the chevron square and the
    /// tops of the lines. The value gets its width first, up to half the
    /// room; the label takes what is left.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let (pad, gap) = (s.px(u32::from(SPACE.md)), s.px(u32::from(SPACE.sm)));
        let (px, block, lh) = self.block();
        let inner = Rect { y: at.y, h: at.h, ..inset(at, pad) };
        let side = if self.chevron { s.px(CHEVRON) } else { 0 };
        let (rest, mark) = split_left(inner, inner.w.saturating_sub(side));
        let room = if self.chevron { rest.w.saturating_sub(gap) } else { rest.w };
        let vw = self.value.map_or(0, |v| text::width(v, px).min(room / 2));
        let used = if vw > 0 { vw.saturating_add(gap) } else { 0 };
        let label_y = at.y.saturating_add(at.h.saturating_sub(block) / 2);
        let note_y = label_y.saturating_add(lh).saturating_add(s.px(LINE_GAP));
        let top = |y: u32| i32::try_from(y).unwrap_or(i32::MAX);
        Parts {
            body: at,
            label: Rect { w: room.saturating_sub(used), ..rest },
            label_top: top(label_y),
            note_top: top(note_y),
            value: Rect { x: rest.x.saturating_add(room - vw), w: vw, ..rest },
            value_top: text::centre_top(at.y, at.h, px),
            chevron: centre(mark, side, side),
            px,
        }
    }
}
