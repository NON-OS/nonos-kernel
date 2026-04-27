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

use crate::graphics::framebuffer::fill_rounded_rect;
use crate::graphics::window::settings::render::{draw_string, draw_toggle};
use crate::sys::settings as sys;

const BG: u32 = 0xFF161B22;
const BTN: u32 = 0xFF21262D;
const SEL: u32 = 0xFF1F6FEB;
const TEXT: u32 = 0xFFE6EDF3;
const DIM: u32 = 0xFF7D8590;

pub(crate) fn draw(x: u32, y: u32, w: u32) {
    let by = y + 360;
    fill_rounded_rect(x + 16, by, w - 32, 140, 8, BG);
    draw_string(x + 28, by + 12, b"Accessibility", TEXT);
    draw_toggle(x + w - 80, by + 32, sys::high_contrast());
    draw_string(x + 28, by + 38, b"High Contrast", DIM);
    draw_toggle(x + w - 80, by + 62, sys::animations_enabled());
    draw_string(x + 28, by + 68, b"Animations", DIM);
    draw_size_row(x + 28, by + 98, b"Font", sys::font_size());
    draw_size_row(x + 28 + (w - 56) / 2, by + 98, b"Cursor", sys::cursor_size());
}

fn draw_size_row(x: u32, y: u32, label: &[u8], val: u8) {
    draw_string(x, y, label, DIM);
    let opts: [&[u8]; 3] = [b"S", b"M", b"L"];
    for (i, o) in opts.iter().enumerate() {
        let bx = x + 50 + (i as u32) * 28;
        let sel = i as u8 == val;
        fill_rounded_rect(bx, y - 4, 24, 22, 4, if sel { SEL } else { BTN });
        draw_string(bx + 8, y, o, if sel { TEXT } else { DIM });
    }
}

pub(crate) fn handle_click(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let by = cy + 360;
    let toggle_x = cx + cw - 80;
    if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
        if my >= (by + 32) as i32 && my < (by + 52) as i32 {
            sys::set_high_contrast(!sys::high_contrast());
            return true;
        }
        if my >= (by + 62) as i32 && my < (by + 82) as i32 {
            sys::set_animations_enabled(!sys::animations_enabled());
            return true;
        }
    }
    if my >= (by + 94) as i32 && my < (by + 120) as i32 {
        if let Some(idx) = btn_idx(mx, cx + 78) {
            sys::set_font_size(idx);
            return true;
        }
        let half = (cw - 56) / 2;
        if let Some(idx) = btn_idx(mx, cx + 78 + half) {
            sys::set_cursor_size(idx);
            return true;
        }
    }
    false
}

fn btn_idx(mx: i32, base: u32) -> Option<u8> {
    let rel = mx - base as i32;
    if rel >= 0 && rel < 84 {
        Some((rel / 28) as u8)
    } else {
        None
    }
}
