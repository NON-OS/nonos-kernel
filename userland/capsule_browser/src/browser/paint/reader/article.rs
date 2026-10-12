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

use alloc::format;

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::font::ttf::line_height;

use super::face;
use super::flow::{Flow, QUOTE_IN};
use super::style::{advance, bold, px, Style};
use crate::browser::paint::tokens::palette;
use crate::browser::reader::extract::{minutes, Article};

const LABEL_PX: f32 = 17.0;
const BAR: i32 = 3;

/// `a` as `f` set it, in a column starting at `x`, `scroll` pixels down.
/// Only the lines inside the buffer are drawn.
pub fn paint(fb: &mut PaintBuffer, a: &Article, f: &Flow, x: i32, scroll: i32, fg: u32, dim: u32) {
    let h = fb.height as i32;
    fb.text_ttf(x, f.site_y - scroll, &a.site.to_uppercase(), dim, LABEL_PX);
    if let Some(ty) = f.time_y {
        let read = format!("{} min read", minutes(a.words));
        fb.text_ttf(x, ty - scroll, &read, dim, LABEL_PX);
    }
    for line in &f.lines {
        let (y, size) = (line.y - scroll, px(line.style, f.body));
        if y + 2 * line_height(size) < 0 {
            continue;
        }
        if y > h {
            break;
        }
        let mut lx = x;
        if line.style == Style::Quote {
            bar(fb, x, y, y + advance(line.style, f.body));
            lx += QUOTE_IN;
        }
        face::draw(fb, lx, y, line.text, fg, size, bold(line.style));
    }
}

fn bar(fb: &mut PaintBuffer, x: i32, top: i32, bottom: i32) {
    let (top, bottom) = (top.max(0), bottom.min(fb.height as i32));
    if bottom > top && x >= 0 {
        fb.fill_rect(x as u32, top as u32, BAR as u32, (bottom - top) as u32, palette().accent);
    }
}
