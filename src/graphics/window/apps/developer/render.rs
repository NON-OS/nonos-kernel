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
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};

const BG: u32 = 0xFF0A0A10;
const CARD: u32 = 0xFF14141C;
const ACCENT: u32 = 0xFF00D4FF;
const DIM: u32 = 0xFF606068;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(crate) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, BG);
    draw_tabs(x, y, w);
    let cy = y + 50;
    let ch = h.saturating_sub(50);
    match current_tab() {
        TAB_OVERVIEW => draw_overview(x, cy, w, ch),
        TAB_MY_APPS => super::my_apps::draw(x, cy, w, ch),
        TAB_PUBLISH => super::publish::draw(x, cy, w, ch),
        TAB_ANALYTICS => super::analytics::draw(x, cy, w, ch),
        TAB_DOCS => draw_docs(x, cy, w, ch),
        _ => {}
    }
}

fn draw_tabs(x: u32, y: u32, w: u32) {
    let tabs: [&[u8]; 5] = [b"Overview", b"My Apps", b"Publish", b"Analytics", b"Docs"];
    let mut tx = x + 20;
    for (i, t) in tabs.iter().enumerate() {
        let sel = current_tab() == i as u8;
        let c = if sel { ACCENT } else { DIM };
        txt(tx, y + 18, *t, c);
        if sel {
            fill_rect(tx, y + 38, t.len() as u32 * 8, 2, ACCENT);
        }
        tx += t.len() as u32 * 8 + 24;
    }
    fill_rect(x, y + 48, w, 1, 0xFF252530);
}

fn draw_overview(x: u32, y: u32, w: u32, _h: u32) {
    txt(x + 20, y + 20, b"NONOS Developer Dashboard", 0xFFFFFFFF);
    fill_rounded_rect(x + 20, y + 50, w - 40, 100, 8, CARD);
    txt(x + 36, y + 70, b"Build apps with the NONOS SDK", 0xFFFFFFFF);
    txt(x + 36, y + 92, b"Publish to marketplace with NOX pricing", DIM);
    txt(x + 36, y + 114, b"Track installs and revenue", DIM);
}

fn draw_docs(x: u32, y: u32, _w: u32, _h: u32) {
    txt(x + 20, y + 20, b"SDK Documentation", 0xFFFFFFFF);
    txt(x + 20, y + 50, b"1. Create manifest.json", DIM);
    txt(x + 20, y + 70, b"2. Implement App trait", DIM);
    txt(x + 20, y + 90, b"3. Build with nonos-sdk", DIM);
    txt(x + 20, y + 110, b"4. Publish via dashboard", DIM);
}
