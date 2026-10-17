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

//! Where a dialog's panel, shadow, title, body, note and buttons sit in `at`,
//! which draw and hit share.

use alloc::string::String;
use alloc::vec::Vec;

use super::Dialog;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CARD_RADIUS, DIALOG_LINES, LINE_GAP};
use crate::widgets::rect::{centre, inset};

/// The placed parts of a dialog, in drawing pixels. `area` holds the panel
/// and the shadow under it; `text` holds the `lines`, one every `step` rows
/// from its top. A part with no room is `None`, or no line or button.
pub(super) struct Parts {
    pub(super) area: Rect,
    pub(super) panel: Rect,
    pub(super) shadow: Rect,
    pub(super) radius: u32,
    pub(super) title: Option<Rect>,
    pub(super) text: Rect,
    pub(super) lines: Vec<String>,
    pub(super) step: u32,
    pub(super) note: Option<Rect>,
    pub(super) buttons: Vec<Rect>,
}

impl Dialog<'_> {
    /// The area is the dialog's size centred in `at` and cut to it. The
    /// panel fills it but the rows the shadow drops into, and the shadow is
    /// the panel moved down by its drop. Inside the padding the buttons'
    /// row takes the bottom, and the room above it stacks the title, the
    /// body's lines and the note. When the room is short the title stays
    /// while it fits, then the note, and the body keeps the lines that fit
    /// after them, the last cut with `…`.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let (w, h) = self.size();
        let area = centre(at, w, h);
        let drop = Self::drop().min(area.h);
        let panel = Rect { h: area.h - drop, ..area };
        let shadow = Rect { y: area.y.saturating_add(drop), ..panel };
        let radius = scale().px(CARD_RADIUS).min(panel.w / 2).min(panel.h / 2);
        let (room, buttons) = self.row(inset(panel, Self::pad()));
        let (th, lh, sm) = (Self::title_h(), Self::lh(), Self::sm());
        let title = (th <= room.h).then_some(Rect { h: th, ..room });
        let mut left = title.map_or(0, |_| room.h - th);
        let note = title.is_some() && !self.note.is_empty() && sm + lh <= left;
        left -= if note { sm + lh } else { 0 };
        let most = (0..=DIALOG_LINES).rev().find(|&n| Self::block(n) <= left).unwrap_or(0);
        let lines = self.lines(room.w, most as usize);
        let block = Self::block(lines.len() as u32);
        let text = Rect { y: room.y.saturating_add(th + sm), h: block.saturating_sub(sm), ..room };
        let below = room.y.saturating_add(th + block + sm);
        let note = note.then_some(Rect { y: below, h: lh, ..room });
        let step = lh + scale().px(LINE_GAP);
        Parts { area, panel, shadow, radius, title, text, lines, step, note, buttons }
    }
}
