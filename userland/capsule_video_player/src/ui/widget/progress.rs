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

use nonos_app_skeleton::paint::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::ui::layout::Rect;
use crate::ui::paint::{rrect, shape};

pub const KNOB: u32 = 12;

pub fn span(w: u32, permille: u32) -> u32 {
    (w as u64 * permille.min(1000) as u64 / 1000) as u32
}

pub fn paint_bar(fb: &mut PaintBuffer, r: Rect, permille: u32, fill: u32) {
    let radius = r.h / 2;
    rrect::fill_round(fb, r.x, r.y, r.w, r.h, radius, roles().border.argb());
    let done = span(r.w, permille);
    if done > 0 {
        rrect::fill_round(fb, r.x, r.y, done.max(r.h.min(r.w)), r.h, radius, fill);
    }
}

pub fn paint_scrub(fb: &mut PaintBuffer, r: Rect, permille: u32, buffered: u32) {
    let (radius, theme) = (r.h / 2, roles());
    rrect::fill_round(fb, r.x, r.y, r.w, r.h, radius, theme.border.argb());
    let ahead = span(r.w, buffered);
    if ahead > 0 {
        rrect::fill_round(fb, r.x, r.y, ahead, r.h, radius, theme.border_strong.argb());
    }
    let done = span(r.w, permille);
    if done > 0 {
        rrect::fill_round(fb, r.x, r.y, done, r.h, radius, theme.accent.argb());
    }
    let cx = r.x + done.min(r.w.saturating_sub(1));
    shape::circle(fb, cx, r.y + r.h / 2, KNOB / 2, theme.text.argb());
}
