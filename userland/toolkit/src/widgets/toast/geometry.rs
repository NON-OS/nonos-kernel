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

//! Where a toast's panel, shadow, bar, lines and action sit in `at`, which
//! draw and hit share.

use alloc::string::String;
use alloc::vec::Vec;

use super::Toast;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CONTROL_H, CONTROL_RADIUS, LINE_GAP, SPACE};
use crate::font::ttf::line_height;
use crate::widgets::rect::{centre, inset, split_left};

/// The placed parts of a toast, in drawing pixels. `room` holds the `lines`,
/// one every `step` rows from its top.
pub(super) struct Parts {
    pub(super) body: Rect,
    pub(super) shadow: Rect,
    pub(super) radius: u32,
    pub(super) bar: Rect,
    pub(super) room: Rect,
    pub(super) lines: Vec<String>,
    pub(super) step: u32,
    pub(super) action: Option<Rect>,
}

impl Toast<'_> {
    /// The panel fills `at` but the bottom rows the shadow drops into, and the
    /// shadow is the panel moved down by its drop. Inside `SPACE.sm` of the
    /// panel's edge, the bar runs its full height at the left, then after
    /// `SPACE.md` the text's room, then the action, `CONTROL_H` tall, at the
    /// right, both centred vertically. Two lines are drawn when two fit, else
    /// one, else none; with no room for a line the action is left out too,
    /// since its label would spill out of the panel.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let s = scale();
        let sp = |d: u16| s.px(u32::from(d));
        let drop = Self::drop().min(at.h);
        let body = Rect { h: at.h - drop, ..at };
        let shadow = Rect { y: at.y.saturating_add(drop), ..body };
        let radius = s.px(CONTROL_RADIUS).min(body.h / 2).min(body.w / 2);
        let inner = inset(body, sp(SPACE.sm));
        let (bar, rest) = split_left(inner, sp(SPACE.xs));
        let (_, rest) = split_left(rest, sp(SPACE.md));
        let (room_w, button_w) = self.across(rest.w);
        let (lh, gap) = (line_height(Self::px()).max(0) as u32, s.px(LINE_GAP));
        let fit = (0..=2u32).rev().find(|n| n * lh + n.saturating_sub(1) * gap <= inner.h);
        let lines = self.lines(room_w, fit.unwrap_or(0) as usize);
        let n = lines.len() as u32;
        let block = n * lh + n.saturating_sub(1) * gap;
        let room = centre(Rect { w: room_w, ..rest }, room_w, block);
        let slot = Rect { x: rest.x.saturating_add(rest.w - button_w), w: button_w, ..rest };
        let shown = !self.action.is_empty() && lh <= inner.h;
        let action = shown.then(|| centre(slot, button_w, s.px(CONTROL_H)));
        Parts { body, shadow, radius, bar, room, lines, step: lh + gap, action }
    }
}
