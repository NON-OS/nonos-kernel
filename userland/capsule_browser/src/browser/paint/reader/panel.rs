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
use nonos_toolkit::font::ttf::line_height;

use super::{controls, face};
use crate::browser::paint::clip;
use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::tokens::palette;
use crate::browser::shell::kept::ReaderPrefs;
use crate::browser::ui::reader_geom::{ReaderGeom, MIN_W};
use crate::browser::ui::rect::Rect;

const RADIUS: u32 = 14;
const SPREAD: u32 = 12;
const TITLE_PX: f32 = 18.0;
pub const LABEL_PX: f32 = 17.0;
const CLOSE: i32 = 16;
const LABELS: [&str; 3] = ["Appearance", "Text size", "Content width"];

/// The reader settings card: its title and close button, then appearance,
/// text size, content width and the reading-time switch.
pub fn paint(p: &ReaderPrefs, g: &ReaderGeom, fb: &mut PaintBuffer) {
    if g.panel.w < MIN_W {
        return;
    }
    clip::panel(fb, g.panel, RADIUS, SPREAD, palette().surface, palette().edge);
    let ty = g.head.y + (g.head.h - line_height(TITLE_PX)) / 2;
    face::draw(fb, g.head.x, ty, "Reader Settings", palette().ink, TITLE_PX, true);
    let (cx, cy) = (g.close.x + g.close.w / 2, g.close.y + g.close.h / 2);
    glyph::draw(fb, Glyph::Close, cx, cy, CLOSE, palette().muted);
    for (r, s) in g.labels.iter().zip(LABELS) {
        label(fb, *r, s, palette().muted);
    }
    controls::swatches(p, g, fb);
    controls::size(p, g, fb);
    controls::widths(p, g, fb);
    label(fb, g.time, "Show reading time", palette().ink2);
    switch(p.show_time, g.switch, fb);
}

/// `s` at the left of `r`, centred on its height.
pub fn label(fb: &mut PaintBuffer, r: Rect, s: &str, argb: u32) {
    fb.text_ttf(r.x, r.y + (r.h - line_height(LABEL_PX)) / 2, s, argb, LABEL_PX);
}

fn switch(on: bool, r: Rect, fb: &mut PaintBuffer) {
    let track = if on { palette().accent } else { palette().disabled };
    fb.fill_round(r.x as u32, r.y as u32, r.w as u32, r.h as u32, r.h as u32 / 2, track);
    let d = r.h - 4;
    let x = if on { r.right() - 2 - d } else { r.x + 2 };
    fb.fill_round(
        x as u32,
        (r.y + 2) as u32,
        d as u32,
        d as u32,
        d as u32 / 2,
        palette().on_accent,
    );
}
