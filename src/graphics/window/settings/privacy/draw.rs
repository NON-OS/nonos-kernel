// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::graphics::framebuffer::fill_rounded_rect;
use crate::graphics::window::settings::render::{draw_string, draw_toggle};
use crate::graphics::window::settings::state::*;

const BG_CARD: u32 = 0xFF161B22;
const BG_BTN: u32 = 0xFF21262D;
const BG_BTN_SEL: u32 = 0xFF1F6FEB;
const BG_DANGER: u32 = 0xFF7F1D1D;
const TEXT: u32 = 0xFFE6EDF3;
const TEXT_DIM: u32 = 0xFF7D8590;

pub(crate) fn draw(x: u32, y: u32, w: u32) {
    let cw = w - 32;
    fill_rounded_rect(x + 16, y, cw, 90, 8, BG_CARD);
    draw_string(x + 28, y + 12, b"Privacy Mode", TEXT);
    draw_string(x + 28, y + 28, b"Select privacy level", TEXT_DIM);
    let modes: [&[u8]; 4] = [b"Std", b"Anon", b"Max", b"Iso"];
    let current = get_privacy_mode();
    let bw = (cw - 48) / 4;
    for (i, name) in modes.iter().enumerate() {
        let bx = x + 28 + (i as u32) * (bw + 4);
        let sel = current == i as u8;
        fill_rounded_rect(bx, y + 52, bw, 26, 4, if sel { BG_BTN_SEL } else { BG_BTN });
        let tc = if sel { TEXT } else { TEXT_DIM };
        let tx = bx + (bw - (name.len() as u32 * 8)) / 2;
        draw_string(tx, y + 58, name, tc);
    }
    fill_rounded_rect(x + 16, y + 100, cw, 110, 8, BG_CARD);
    draw_row(x + 28, y + 112, cw - 24, b"NYM Mixnet", is_nym_enabled());
    draw_row(x + 28, y + 148, cw - 24, b"MAC Random", is_privacy_enabled());
    draw_row(x + 28, y + 184, cw - 24, b"ZeroState", is_zero_state_enabled());
    fill_rounded_rect(x + 16, y + 220, cw, 80, 8, BG_CARD);
    draw_row(x + 28, y + 232, cw - 24, b"WiFi Auto", is_wifi_autoconnect());
    draw_autolock(x + 28, y + 268, cw - 24);
    fill_rounded_rect(x + 16, y + 310, cw, 60, 8, BG_CARD);
    draw_string(x + 28, y + 322, b"Data", TEXT);
    let btn_w = (cw - 36) / 2;
    fill_rounded_rect(x + 28, y + 340, btn_w, 24, 4, BG_DANGER);
    draw_string(x + 36, y + 345, b"Clear", TEXT);
    fill_rounded_rect(x + 36 + btn_w, y + 340, btn_w, 24, 4, BG_BTN);
    draw_string(x + 44 + btn_w, y + 345, b"History", TEXT_DIM);
}

fn draw_autolock(x: u32, y: u32, _w: u32) {
    draw_string(x, y + 6, b"Auto-Lock", TEXT);
    let val = crate::sys::settings::auto_lock_timeout();
    let vals: [&[u8]; 4] = [b"Off", b"1m", b"5m", b"15m"];
    let idx = match val {
        0 => 0,
        1 => 1,
        5 => 2,
        _ => 3,
    };
    for (i, v) in vals.iter().enumerate() {
        let bx = x + 100 + (i as u32) * 40;
        let sel = i == idx;
        fill_rounded_rect(bx, y, 36, 24, 4, if sel { BG_BTN_SEL } else { BG_BTN });
        draw_string(bx + 8, y + 6, v, if sel { TEXT } else { TEXT_DIM });
    }
}

fn draw_row(x: u32, y: u32, w: u32, title: &[u8], enabled: bool) {
    draw_string(x, y + 6, title, TEXT);
    draw_toggle(x + w - 48, y, enabled);
}
