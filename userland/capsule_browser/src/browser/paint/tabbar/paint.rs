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

use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::tokens::{self, palette};
use crate::browser::state::{State, View};
use crate::browser::tabs::Tabs;
use crate::browser::ui::fit;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::tabs_geom::{close_rect, plus_rect, tab_rect, Strip};

use super::label::label;

const TEXT_PX: f32 = 17.0;
const ICON: i32 = 16;
const PAD: i32 = 10;
const RADIUS: u32 = 10;
const SPREAD: u32 = 3;

/// The titlebar tab strip. The frame paints behind it, so only the active
/// tab gets a surface of its own.
pub fn paint(tabs: &Tabs, fb: &mut PaintBuffer) {
    let s =
        Strip { n: tabs.list.len(), active: tabs.active, w: fb.width as i32, h: fb.height as i32 };
    for (i, st) in tabs.list.iter().enumerate() {
        if let Some(r) = tab_rect(&s, i) {
            tab(fb, st, r, i == tabs.active);
        }
    }
    let p = plus_rect(&s);
    glyph::draw(fb, Glyph::Plus, p.x + p.w / 2, p.y + p.h / 2, ICON, tokens::ON_FRAME);
}

fn tab(fb: &mut PaintBuffer, st: &State, r: Rect, active: bool) {
    let (x, y, w, h) = (r.x as u32, r.y as u32, r.w as u32, r.h as u32);
    if active {
        fb.shadow_round(x, y, w, h, RADIUS, SPREAD, palette().shadow);
        fb.fill_round(x, y, w, h, RADIUS, palette().surface);
    }
    let ink = if active { palette().ink } else { tokens::ON_FRAME };
    let (cx, cy) = (r.x + PAD + ICON / 2, r.y + r.h / 2);
    if st.loading() {
        fb.circle(cx as u32, cy as u32, 4, palette().teal);
    } else {
        let g = if matches!(st.view, View::Home) { Glyph::Home } else { Glyph::Globe };
        glyph::draw(fb, g, cx, cy, ICON, ink);
    }
    let c = close_rect(r);
    glyph::draw(fb, Glyph::Close, c.x + c.w / 2, c.y + c.h / 2, c.w * 2 / 3, ink);
    let tx = r.x + PAD + ICON + PAD / 2;
    let shown = fit::truncate_to(&label(st), c.x - PAD / 2 - tx, |t| measure_ttf(t, TEXT_PX));
    fb.text_ttf(tx, r.y + (r.h - line_height(TEXT_PX)) / 2, &shown, ink, TEXT_PX);
}
