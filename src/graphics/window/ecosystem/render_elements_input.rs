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

use super::render_helpers::{COLOR_ACCENT, COLOR_INPUT_BG, COLOR_INPUT_BORDER, COLOR_WARNING};
use super::render_utils::draw_border_thin;
use crate::apps::ecosystem::browser::engine::ImageData;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, put_pixel};

pub fn draw_input_element(ex: u32, line_y: u32, name: &str, width: u32, max_width: u32) {
    let iw = width.min(max_width);
    fill_rect(ex, line_y, iw, 20, COLOR_INPUT_BG);
    draw_border_thin(ex, line_y, iw, 20, COLOR_INPUT_BORDER);
    let mut cx = ex + 4;
    for &ch in name.as_bytes() {
        if cx + 8 > ex + iw {
            break;
        }
        draw_char(cx, line_y + 2, ch, COLOR_WARNING);
        cx += 8;
    }
}

pub fn draw_button_element(ex: u32, line_y: u32, text: &str, max_width: u32) {
    let bw = (text.len() as u32 * 8 + 16).min(max_width);
    fill_rect(ex, line_y, bw, 20, 0xFF2C2C4E);
    draw_border_thin(ex, line_y, bw, 20, COLOR_ACCENT);
    let mut cx = ex + 8;
    for &ch in text.as_bytes() {
        if cx + 8 > ex + bw {
            break;
        }
        draw_char(cx, line_y + 2, ch, COLOR_ACCENT);
        cx += 8;
    }
}

pub fn draw_select_element(ex: u32, line_y: u32, name: &str, value: &str, max_width: u32) {
    let label = if value.is_empty() { name } else { value };
    let sw = ((label.len() as u32 + 4) * 8).min(max_width);
    fill_rect(ex, line_y, sw, 20, COLOR_INPUT_BG);
    draw_border_thin(ex, line_y, sw, 20, COLOR_INPUT_BORDER);
    let mut cx = ex + 4;
    for &ch in label.as_bytes() {
        if cx + 8 > ex + sw - 16 {
            break;
        }
        draw_char(cx, line_y + 2, ch, 0xFFE0E0E0);
        cx += 8;
    }
    draw_char(ex + sw - 12, line_y + 2, b'v', 0xFF888888);
}

pub fn draw_textarea_element(
    ex: u32,
    line_y: u32,
    name: &str,
    width: u32,
    height: u32,
    max_width: u32,
) {
    let tw = width.min(max_width);
    let th = height.min(200);
    fill_rect(ex, line_y, tw, th, COLOR_INPUT_BG);
    draw_border_thin(ex, line_y, tw, th, COLOR_INPUT_BORDER);
    let mut cx = ex + 4;
    for &ch in name.as_bytes() {
        if cx + 8 > ex + tw {
            break;
        }
        draw_char(cx, line_y + 2, ch, 0xFF888888);
        cx += 8;
    }
}

pub fn blit_image_data(x: u32, y: u32, data: &ImageData, max_width: u32, clip_bottom: u32) {
    let draw_w = data.width.min(max_width);
    for py in 0..data.height {
        let screen_y = y + py;
        if screen_y >= clip_bottom {
            break;
        }
        for px in 0..draw_w {
            let idx = (py * data.width + px) as usize;
            if idx < data.pixels.len() {
                let color = data.pixels[idx];
                if color & 0xFF000000 != 0 {
                    put_pixel(x + px, screen_y, color);
                }
            }
        }
    }
}
