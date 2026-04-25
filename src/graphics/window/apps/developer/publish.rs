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

use super::publish_state::*;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};

const ACCENT: u32 = 0xFF00D4FF;
const DIM: u32 = 0xFF606068;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(super) fn draw(x: u32, y: u32, _w: u32, _h: u32) {
    txt(x + 20, y + 20, b"Publish New App", 0xFFFFFFFF);
    txt(x + 20, y + 50, b"App Name:", DIM);
    draw_input(x + 20, y + 70, 300, name_buf(), name_len(), focus() == 0);
    txt(x + 20, y + 120, b"Price (NOX):", DIM);
    draw_input(x + 20, y + 140, 100, price_buf(), price_len(), focus() == 1);
    fill_rounded_rect(x + 20, y + 200, 120, 36, 6, ACCENT);
    txt(x + 44, y + 210, b"Publish", 0xFF000000);
}

fn draw_input(x: u32, y: u32, w: u32, buf: &[u8], len: u8, focused: bool) {
    let bg = if focused { 0xFF1E1E28 } else { 0xFF16161E };
    fill_rounded_rect(x, y, w, 36, 6, bg);
    for i in 0..len as usize {
        draw_char(x + 8 + i as u32 * 8, y + 10, buf[i], 0xFFFFFFFF);
    }
    if focused {
        fill_rect(x + 8 + len as u32 * 8, y + 8, 2, 20, ACCENT);
    }
}

pub(super) fn handle_click(rx: u32, ry: u32) -> bool {
    if ry >= 70 && ry < 106 {
        set_focus(0);
        return true;
    }
    if ry >= 140 && ry < 176 {
        set_focus(1);
        return true;
    }
    if ry >= 200 && ry < 236 && rx >= 20 && rx < 140 {
        publish_app();
        return true;
    }
    false
}

pub(super) fn handle_key(ch: u8) {
    if focus() == 0 {
        handle_name_key(ch);
    } else {
        handle_price_key(ch);
    }
}

fn handle_name_key(ch: u8) {
    let len = name_len();
    if ch == 8 && len > 0 {
        set_name_len(len - 1);
    } else if ch >= 32 && ch < 127 && len < 31 {
        unsafe {
            NAME_BUF[len as usize] = ch;
        }
        set_name_len(len + 1);
    }
}

fn handle_price_key(ch: u8) {
    let len = price_len();
    if ch == 8 && len > 0 {
        set_price_len(len - 1);
    } else if ch >= b'0' && ch <= b'9' && len < 7 {
        unsafe {
            PRICE_BUF[len as usize] = ch;
        }
        set_price_len(len + 1);
    }
}

pub(super) fn publish_app() {
    let nl = name_len() as usize;
    if nl == 0 {
        crate::graphics::window::notify_error(b"Enter app name");
        return;
    }
    let mut m = crate::sdk::manifest::AppManifest::empty();
    unsafe {
        m.name[..nl].copy_from_slice(&NAME_BUF[..nl]);
    }
    crate::sdk::registry::register_app(m);
    crate::graphics::window::notify_success(b"App published!");
}
