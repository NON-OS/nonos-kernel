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

use crate::graphics::design_system::colors::*;
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect, put_pixel};

#[derive(Clone, Copy)]
pub struct ColorPicker {
    pub hue: u16,
    pub saturation: u8,
    pub brightness: u8,
}

impl ColorPicker {
    pub const fn new() -> Self {
        Self { hue: 0, saturation: 100, brightness: 100 }
    }

    pub fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        let (h, s, v) = rgb_to_hsv(r, g, b);
        Self { hue: h, saturation: s, brightness: v }
    }

    pub fn to_rgb(&self) -> (u8, u8, u8) {
        hsv_to_rgb(self.hue, self.saturation, self.brightness)
    }

    pub fn to_u32(&self) -> u32 {
        let (r, g, b) = self.to_rgb();
        0xFF000000 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
    }

    pub fn draw(&self, x: u32, y: u32) {
        fill_rounded_rect(x, y, 200, 180, 8, BG_ELEVATED);
        self.draw_gradient(x + 12, y + 12, 140, 100);
        self.draw_hue_bar(x + 160, y + 12, 20, 100);
        fill_rect(x + 12, y + 124, 40, 40, self.to_u32());
        let mut hex_buf = [b'#', 0, 0, 0, 0, 0, 0];
        let (r, g, b) = self.to_rgb();
        format_hex_color(r, g, b, &mut hex_buf[1..]);
        draw_text(x + 60, y + 140, &hex_buf, TEXT_PRIMARY);
    }

    fn draw_gradient(&self, x: u32, y: u32, w: u32, h: u32) {
        for py in 0..h {
            for px in 0..w {
                let s = (px * 100 / w) as u8;
                let v = 100 - (py * 100 / h) as u8;
                let (r, g, b) = hsv_to_rgb(self.hue, s, v);
                let color = 0xFF000000 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
                put_pixel(x + px, y + py, color);
            }
        }
    }

    fn draw_hue_bar(&self, x: u32, y: u32, w: u32, h: u32) {
        for py in 0..h {
            let hue = (py * 360 / h) as u16;
            let (r, g, b) = hsv_to_rgb(hue, 100, 100);
            let color = 0xFF000000 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
            fill_rect(x, y + py, w, 1, color);
        }
    }
}

fn hsv_to_rgb(h: u16, s: u8, v: u8) -> (u8, u8, u8) {
    if s == 0 {
        let vv = (v as u32 * 255 / 100) as u8;
        return (vv, vv, vv);
    }
    let h = (h % 360) as u32;
    let s = s as u32;
    let v = v as u32;
    let region = h / 60;
    let rem = (h % 60) * 255 / 60;
    let p = (v * (100 - s) * 255 / 10000) as u8;
    let q = (v * (100 - (s * rem / 255)) * 255 / 10000) as u8;
    let t = (v * (100 - (s * (255 - rem) / 255)) * 255 / 10000) as u8;
    let vv = (v * 255 / 100) as u8;
    match region {
        0 => (vv, t, p),
        1 => (q, vv, p),
        2 => (p, vv, t),
        3 => (p, q, vv),
        4 => (t, p, vv),
        _ => (vv, p, q),
    }
}

fn rgb_to_hsv(r: u8, g: u8, b: u8) -> (u16, u8, u8) {
    let (r, g, b) = (r as u32, g as u32, b as u32);
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let delta = max - min;
    let v = (max * 100 / 255) as u8;
    if delta == 0 {
        return (0, 0, v);
    }
    let s = (delta * 100 / max) as u8;
    let h = if max == r {
        (60 * (g as i32 - b as i32) / delta as i32 + 360) % 360
    } else if max == g {
        (60 * (b as i32 - r as i32) / delta as i32 + 120) % 360
    } else {
        (60 * (r as i32 - g as i32) / delta as i32 + 240) % 360
    };
    (h as u16, s, v)
}

fn format_hex_color(r: u8, g: u8, b: u8, buf: &mut [u8]) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    buf[0] = HEX[(r >> 4) as usize];
    buf[1] = HEX[(r & 0xF) as usize];
    buf[2] = HEX[(g >> 4) as usize];
    buf[3] = HEX[(g & 0xF) as usize];
    buf[4] = HEX[(b >> 4) as usize];
    buf[5] = HEX[(b & 0xF) as usize];
}
