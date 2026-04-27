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

use super::state::*;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rect;

const BG: u32 = 0xFF0A0A10;
const ACCENT: u32 = 0xFF00D4FF;
const DIM: u32 = 0xFF606068;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(crate) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, BG);
    draw_header(x, y, w);
    let cy = y + 50;
    let ch = h.saturating_sub(50);
    match view() {
        VIEW_LIST => super::list::draw(x, cy, w, ch),
        VIEW_CHAT => super::chat::draw(x, cy, w, ch),
        VIEW_CREATE => super::create::draw(x, cy, w, ch),
        VIEW_DASHBOARD => super::dashboard::draw(x, cy, w, ch),
        _ => {}
    }
}

fn draw_header(x: u32, y: u32, w: u32) {
    txt(x + 20, y + 16, b"AI Agents", ACCENT);
    fill_rect(x + 20, y + 38, 72, 2, ACCENT);
    let tabs =
        [(b"Dashboard" as &[u8], VIEW_DASHBOARD), (b"Agents", VIEW_LIST), (b"Create", VIEW_CREATE)];
    let mut tx = x + w - 260;
    for (name, v) in tabs {
        let sel = view() == v;
        let c = if sel { ACCENT } else { DIM };
        txt(tx, y + 16, name, c);
        if sel {
            fill_rect(tx, y + 38, name.len() as u32 * 8, 2, ACCENT);
        }
        tx += name.len() as u32 * 8 + 16;
    }
}
