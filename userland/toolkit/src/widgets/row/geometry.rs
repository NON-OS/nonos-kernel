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

//! Where a row's label, note, value, trailing box and chevron sit, which draw
//! and hit share.

use super::Row;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{LINE_GAP, SPACE};
use crate::widgets::text;

/// The placed parts of a row, in drawing pixels.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) label: Rect,
    pub(super) label_top: i32,
    pub(super) note_top: i32,
    pub(super) value: Rect,
    pub(super) value_top: i32,
    pub(super) trailing: Rect,
    pub(super) chevron: Rect,
    pub(super) px: f32,
}

impl Row<'_> {
    /// The body, the label column, the value box, the trailing box, the
    /// chevron square and the tops of the lines. The value gets its width
    /// first, up to half the text lane; the label takes what is left.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let gap = s.px(u32::from(SPACE.sm));
        let (px, block, lh) = self.block();
        let (lane, trailing, chevron) = self.lanes(at);
        let vw = self.value.map_or(0, |v| text::width(v, px).min(lane.w / 2));
        let used = if vw > 0 { vw.saturating_add(gap) } else { 0 };
        let label_y = at.y.saturating_add(at.h.saturating_sub(block) / 2);
        let note_y = label_y.saturating_add(lh).saturating_add(s.px(LINE_GAP));
        let top = |y: u32| i32::try_from(y).unwrap_or(i32::MAX);
        Parts {
            body: at,
            label: Rect { w: lane.w.saturating_sub(used), ..lane },
            label_top: top(label_y),
            note_top: top(note_y),
            value: Rect { x: lane.x.saturating_add(lane.w - vw), w: vw, ..lane },
            value_top: text::centre_top(at.y, at.h, px),
            trailing,
            chevron,
            px,
        }
    }
}
