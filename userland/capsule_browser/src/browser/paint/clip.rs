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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::paint::mixer::lerp_argb;

use crate::browser::paint::tokens::palette;
use crate::browser::ui::rect::Rect;

/// `r` filled with rounded corners in an opaque `argb`. Where a scrolled
/// page has carried it above the top edge it is cut flat there.
pub fn round(fb: &mut PaintBuffer, r: Rect, radius: u32, argb: u32) {
    let top = r.y.max(0);
    let h = r.bottom() - top;
    if h <= 0 || r.w <= 0 || r.x < 0 {
        return;
    }
    let (x, w) = (r.x as u32, r.w as u32);
    fb.fill_round(x, top as u32, w, h as u32, radius, argb);
    if r.y < 0 {
        fb.blend_rect(x, 0, w, (radius as i32).min(h) as u32, argb);
    }
}

/// A card: soft shadow, fill and hairline edge. Cut flat at the top edge
/// like `round`, where it keeps its sides but loses the shadow.
pub fn panel(fb: &mut PaintBuffer, r: Rect, radius: u32, spread: u32, fill: u32, edge: u32) {
    if r.w <= 2 || r.x < 0 || r.bottom() <= 0 {
        return;
    }
    let (x, w) = (r.x as u32, r.w as u32);
    if r.y >= 0 {
        let (y, h) = (r.y as u32, r.h as u32);
        fb.shadow_round(x, y, w, h, radius, spread, palette().shadow);
        fb.fill_round(x, y, w, h, radius, fill);
        fb.stroke_round(x, y, w, h, radius, 1, edge);
        return;
    }
    let h = r.bottom();
    let cut = (radius as i32).min(h) as u32;
    fb.stroke_round(x, 0, w, h as u32, radius, 1, edge);
    fb.fill_round(x + 1, 0, w - 2, (h - 1).max(0) as u32, radius, fill);
    fb.blend_rect(x + 1, 0, w - 2, cut, fill);
    fb.fill_rect(x, 0, 1, cut, edge);
    fb.fill_rect(x + w - 1, 0, 1, cut, edge);
}

/// A vertical gradient over `r`. Above the top edge it is cut, and the part
/// left starts at the colour it had there.
pub fn gradient_v(fb: &mut PaintBuffer, r: Rect, top: u32, bottom: u32) {
    if r.bottom() <= 0 || r.w <= 0 || r.h <= 1 || r.x < 0 {
        return;
    }
    let skip = (-r.y).max(0);
    let from = lerp_argb(top, bottom, (skip * 255 / (r.h - 1)).min(255) as u32);
    let y = r.y.max(0) as u32;
    fb.gradient_v(r.x as u32, y, r.w as u32, (r.bottom() - r.y.max(0)) as u32, from, bottom);
}
