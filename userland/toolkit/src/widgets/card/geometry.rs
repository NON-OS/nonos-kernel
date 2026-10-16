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

//! Where a card's head, text and content sit, which draw and hit share.

use super::Card;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CARD_HEAD_H, CARD_HEAD_NOTE_H, LINE_GAP, SPACE};
use crate::design::text_role::TextRole;
use crate::font::ttf::line_height;
use crate::widgets::rect::{inset, split_top};

/// The placed parts of a card, in drawing pixels.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) text: Rect,
    pub(super) title_top: i32,
    pub(super) note_top: i32,
    pub(super) content: Rect,
    pub(super) px: f32,
}

impl Card<'_> {
    /// Height of the head in drawing pixels, 0 when there is no title.
    pub fn head_h(&self) -> u32 {
        if self.title.is_none() {
            return 0;
        }
        let logical = if self.note.is_some() { CARD_HEAD_NOTE_H } else { CARD_HEAD_H };
        scale().px(logical).max(self.block().1)
    }

    /// The card's body, its head text box, the tops of its two lines and the
    /// content area below the head.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let pad = scale().px(u32::from(SPACE.lg));
        let (head, rest) = split_top(at, self.head_h());
        let (px, block, lh) = self.block();
        let title_y = head.y.saturating_add(head.h.saturating_sub(block) / 2);
        let note_y = title_y.saturating_add(lh).saturating_add(scale().px(LINE_GAP));
        let top = |y: u32| i32::try_from(y).unwrap_or(i32::MAX);
        Parts {
            body: at,
            text: Rect { y: head.y, h: head.h, ..inset(at, pad) },
            title_top: top(title_y),
            note_top: top(note_y),
            content: Rect { h: rest.h.saturating_sub(pad), ..rest },
            px,
        }
    }

    /// The body text size, the height of the stacked head text and one line.
    fn block(&self) -> (f32, u32, u32) {
        let px = scale().font(TextRole::Body.px());
        let lh = line_height(px).max(0) as u32;
        let gap = scale().px(LINE_GAP);
        let block = if self.note.is_some() { lh.saturating_mul(2).saturating_add(gap) } else { lh };
        (px, block, lh)
    }
}
