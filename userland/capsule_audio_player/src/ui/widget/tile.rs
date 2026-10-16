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

//! Stat tiles and the storage meter.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::with_alpha;
use nonos_toolkit::theme::roles;

use crate::ui::geometry::Rect;
use crate::ui::icon::{Glyph, Icons};
use crate::ui::metrics::{line_h, DATA, LABEL, S3, S4};
use crate::ui::paint::{card, fill, text, text_right};
use crate::ui::text::upper;

pub const TILE_H: i32 = 96;

pub fn stat_tile(fb: &mut PaintBuffer, icons: &Icons, r: Rect, value: &str, label: &str, g: Glyph) {
    let t = roles();
    card(fb, r);
    let inner = r.pad(S4, (r.h - 20).max(0) / 2);
    icons.draw(fb, Rect::new(inner.x, inner.y, 20, 20), g, with_alpha(t.accent.argb(), 0xCC));
    let lx = inner.x + 20 + S3;
    text(fb, lx, inner.y + (20 - line_h(LABEL)) / 2, &upper(label), t.muted.argb(), LABEL);
    let vr = Rect::new(lx, inner.y + (20 - line_h(DATA)) / 2, inner.right() - lx, line_h(DATA));
    text_right(fb, vr, value, t.text.argb(), DATA);
}

pub fn storage_meter(fb: &mut PaintBuffer, r: Rect, used: u32, total: u32, used_label: &str) {
    let t = roles();
    card(fb, r);
    let inner = r.pad(S4, S4);
    text(fb, inner.x, inner.y, &upper("Storage"), t.muted.argb(), LABEL);
    text_right(fb, Rect::new(inner.x, inner.y, inner.w, line_h(LABEL)), used_label, t.text.argb(), LABEL);
    let bar = Rect::new(inner.x, inner.bottom() - 10, inner.w, 8);
    fill(fb, bar, 4, t.sunken.argb());
    let pct = if total == 0 { 0 } else { (used * 100 / total).min(100) };
    let w = bar.w * pct as i32 / 100;
    let c = if pct > 80 { t.warn } else if pct > 40 { t.accent } else { t.ok };
    if w > 0 {
        fill(fb, Rect::new(bar.x, bar.y, w, bar.h), 4, c.argb());
    }
    fill(fb, Rect::new(bar.x, bar.y - S3 - 2, inner.w, 1), 0, t.border_soft.argb());
}
