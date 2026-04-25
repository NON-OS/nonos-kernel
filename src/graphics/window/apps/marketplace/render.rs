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

use super::apps::get_apps;
use super::cards::{draw_card, draw_empty};
use super::state::{category, scroll, selected, CAT_ALL, CAT_BROWSER, CAT_SOCIAL, CAT_TOOLS};
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rect;

const BG: u32 = 0xFF0C0C12;
const ACCENT: u32 = 0xFF00D4FF;
const DIM: u32 = 0xFF606068;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(crate) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, BG);
    draw_header(x, y);
    draw_categories(x, y + 50);
    let apps = get_apps(category());
    if apps.is_empty() {
        draw_empty(x, y, w, h);
        return;
    }
    draw_grid(x, y + 100, w, h.saturating_sub(100), &apps);
}

fn draw_header(x: u32, y: u32) {
    txt(x + 20, y + 16, b"NOX App Store", ACCENT);
    fill_rect(x + 20, y + 38, 104, 2, ACCENT);
}

fn draw_categories(x: u32, y: u32) {
    let cats = [
        (b"All" as &[u8], CAT_ALL),
        (b"Social", CAT_SOCIAL),
        (b"Browser", CAT_BROWSER),
        (b"Tools", CAT_TOOLS),
    ];
    let mut cx = x + 20;
    let cur = category();
    for (name, cat) in cats {
        let sel = cur == cat;
        let c = if sel { ACCENT } else { DIM };
        txt(cx, y, name, c);
        if sel {
            fill_rect(cx, y + 18, name.len() as u32 * 8, 2, ACCENT);
        }
        cx += name.len() as u32 * 8 + 20;
    }
}

fn draw_grid(x: u32, y: u32, w: u32, h: u32, apps: &[super::apps::AppEntry]) {
    let cols = ((w - 40) / 200).max(1) as usize;
    let scroll_off = scroll();
    let mut cy = y + 10;
    for (i, app) in apps.iter().skip(scroll_off).enumerate() {
        if cy + 90 > y + h {
            break;
        }
        let col = i % cols;
        let cx = x + 20 + (col as u32) * 200;
        if col == 0 && i > 0 {
            cy += 100;
        }
        draw_card(cx, cy, app, selected() == i + scroll_off);
    }
}
