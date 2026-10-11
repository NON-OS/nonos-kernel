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

use nonos_app_skeleton::{measure_ttf, PaintBuffer};
use nonos_toolkit::font::ttf::line_height;

use crate::browser::paint::{clip, tokens};
use crate::browser::ui::fit;
use crate::browser::ui::list_geom::{ListGeom, BAND_H};
use crate::browser::ui::rect::Rect;

pub const PAD: i32 = 16;
pub const GAP: i32 = 16;
pub const PX: f32 = 17.0;
pub const TILE: i32 = 40;
pub const WIDE_TILE: i32 = 52;
const RADIUS: u32 = 14;
const SPREAD: u32 = 4;
const TEXT_X: i32 = PAD + WIDE_TILE + 14;
const LINE_GAP: i32 = 2;

/// The card behind `n` rows and the hairlines between them.
pub fn frame(fb: &mut PaintBuffer, g: &ListGeom, n: usize) {
    clip::panel(fb, g.card(n), RADIUS, SPREAD, tokens::SURFACE, tokens::EDGE);
    let w = (g.frame.w - 2 * PAD).max(0) as u32;
    for i in 1..n {
        let y = g.row_rect(i).y;
        if y >= BAND_H && y < fb.height as i32 {
            fb.fill_rect((g.frame.x + PAD) as u32, y as u32, w, 1, tokens::EDGE);
        }
    }
}

/// True when some of `row` shows below the header band.
pub fn shown(fb: &PaintBuffer, row: Rect) -> bool {
    row.bottom() > BAND_H && row.y < fb.height as i32
}

/// `top` in ink over `below` in muted, both cut to end before `right`.
pub fn lines(fb: &mut PaintBuffer, row: Rect, right: i32, top: &str, below: &str) {
    let (x, lh) = (row.x + TEXT_X, line_height(PX));
    let w = right - GAP - x;
    let cut = |s: &str| fit::truncate_to(s, w, |t| measure_ttf(t, PX));
    let y = row.y + (row.h - 2 * lh - LINE_GAP) / 2;
    fb.text_ttf(x, y, &cut(top), tokens::INK, PX);
    fb.text_ttf(x, y + lh + LINE_GAP, &cut(below), tokens::MUTED, PX);
}

/// A one-row card holding `msg`, for a list with nothing in it.
pub fn empty(fb: &mut PaintBuffer, g: &ListGeom, msg: &str) {
    frame(fb, g, 1);
    let r = g.row_rect(0);
    if shown(fb, r) {
        fb.text_ttf(r.x + PAD, r.y + (r.h - line_height(PX)) / 2, msg, tokens::MUTED, PX);
    }
}
