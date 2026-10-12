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
use nonos_toolkit::paint::mixer::lerp_argb;

use crate::browser::paint::pages::tab_chip;
use crate::browser::paint::pages::tab_head::{cut, head, HEAD_H, PAD};
use crate::browser::paint::start::tile_color;
use crate::browser::paint::{clip, tokens::palette};
use crate::browser::shell::cards::TabCard;
use crate::browser::shell::Shell;
use crate::browser::ui::list_geom::{ListGeom, BAND_H};
use crate::browser::ui::rect::Rect;

const RADIUS: u32 = 14;
const SPREAD: u32 = 4;
const HOST_PX: f32 = 26.0;
const BODY_RADIUS: u32 = 10;
const TINT: u32 = 40;

/// One card, with its group chip, per tab in `shown`; the active one is
/// outlined in accent.
pub fn paint(shell: &Shell, shown: &[usize], g: &ListGeom, fb: &mut PaintBuffer) {
    let cols = g.cols();
    for (j, &i) in shown.iter().enumerate() {
        let r = g.grid_rect(j, cols);
        let Some(c) = shell.cards.get(i) else { continue };
        if r.bottom() > BAND_H && r.y < fb.height as i32 {
            card(fb, r, c);
            tab_chip::paint(fb, r, shell, c.group);
        }
    }
}

fn card(fb: &mut PaintBuffer, r: Rect, c: &TabCard) {
    let edge = if c.active { palette().accent } else { palette().edge };
    clip::panel(fb, r, RADIUS, SPREAD, palette().surface, edge);
    if c.active && r.y >= 0 {
        let (x, y, w, h) = (r.x as u32, r.y as u32, r.w as u32, r.h as u32);
        fb.stroke_round(x, y, w, h, RADIUS, 2, palette().accent);
    }
    let color = tile_color(&c.host);
    head(fb, r, &c.title, &c.host, color);
    let body = Rect::new(r.x + PAD, r.y + HEAD_H, r.w - 2 * PAD, r.h - HEAD_H - PAD);
    clip::round(fb, body, BODY_RADIUS, lerp_argb(palette().surface, color, TINT));
    let big = cut(&c.host, HOST_PX, body.w - 2 * PAD);
    let bx = body.x + (body.w - measure_ttf(&big, HOST_PX)) / 2;
    let by = body.y + (body.h - line_height(HOST_PX)) / 2;
    fb.text_ttf(bx, by, &big, color, HOST_PX);
}
