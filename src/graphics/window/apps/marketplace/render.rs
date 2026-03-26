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

use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};
use crate::graphics::font::draw_char;
use super::apps::get_apps;
use super::state::{category, scroll, selected, CAT_ALL, CAT_SOCIAL, CAT_BROWSER, CAT_TOOLS};

const BG: u32 = 0xFF0C0C12;
const CARD: u32 = 0xFF16161E;
const ACCENT: u32 = 0xFF00D4FF;
const DIM: u32 = 0xFF606068;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() { draw_char(x + i as u32 * 8, y, ch, c); }
}

pub(crate) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, BG);
    draw_header(x, y, w);
    draw_categories(x, y + 50, w);
    let apps = get_apps(category());
    if apps.is_empty() { draw_empty(x, y, w, h); return; }
    let cy = y + 100;
    let ch = h.saturating_sub(100);
    draw_app_grid(x, cy, w, ch, &apps);
}

fn draw_header(x: u32, y: u32, _w: u32) {
    txt(x + 20, y + 16, b"NOX App Store", ACCENT);
    fill_rect(x + 20, y + 38, 104, 2, ACCENT);
}

fn draw_categories(x: u32, y: u32, _w: u32) {
    let cats = [(b"All" as &[u8], CAT_ALL), (b"Social", CAT_SOCIAL), (b"Browser", CAT_BROWSER), (b"Tools", CAT_TOOLS)];
    let mut cx = x + 20;
    let cur = category();
    for (name, cat) in cats {
        let sel = cur == cat;
        let c = if sel { ACCENT } else { DIM };
        txt(cx, y, name, c);
        if sel { fill_rect(cx, y + 18, name.len() as u32 * 8, 2, ACCENT); }
        cx += name.len() as u32 * 8 + 20;
    }
}

fn draw_app_grid(x: u32, y: u32, w: u32, h: u32, apps: &[super::apps::AppEntry]) {
    let cols = ((w - 40) / 200).max(1) as usize;
    let scroll_off = scroll();
    let mut cy = y + 10;
    for (i, app) in apps.iter().skip(scroll_off).enumerate() {
        if cy + 90 > y + h { break; }
        let col = i % cols;
        let cx = x + 20 + (col as u32) * 200;
        if col == 0 && i > 0 { cy += 100; }
        draw_app_card(cx, cy, app, selected() == i + scroll_off);
    }
}

fn draw_app_card(x: u32, y: u32, app: &super::apps::AppEntry, sel: bool) {
    let bg = if sel { 0xFF1E1E28 } else { CARD };
    fill_rounded_rect(x, y, 180, 80, 8, bg);
    let nlen = app.name.iter().position(|&c| c == 0).unwrap_or(64).min(20);
    txt(x + 12, y + 12, &app.name[..nlen], 0xFFFFFFFF);
    txt(x + 12, y + 32, b"Price:", DIM);
    let mut buf = [0u8; 8]; let dlen = fmt_num(app.nox_fee, &mut buf);
    txt(x + 60, y + 32, &buf[..dlen], ACCENT);
    txt(x + 60 + dlen as u32 * 8 + 4, y + 32, b"NOX", DIM);
    txt(x + 12, y + 52, b"Installs:", DIM);
    let ilen = fmt_num(app.installs, &mut buf);
    txt(x + 84, y + 52, &buf[..ilen], 0xFFFFFFFF);
}

fn draw_empty(x: u32, y: u32, w: u32, h: u32) {
    let cx = x + w / 2; let cy = y + h / 2;
    fill_rounded_rect(cx - 100, cy - 60, 200, 120, 8, CARD);
    txt(cx - 56, cy - 30, b"No Apps Yet", 0xFFFFFFFF);
    txt(cx - 80, cy, b"Publish apps via", DIM);
    txt(cx - 80, cy + 20, b"Developer Dashboard", ACCENT);
}

fn fmt_num(mut n: u32, buf: &mut [u8; 8]) -> usize {
    if n == 0 { buf[0] = b'0'; return 1; }
    let mut i = 0;
    while n > 0 && i < 8 { buf[7 - i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    buf.copy_within(8 - i.., 0); i
}
