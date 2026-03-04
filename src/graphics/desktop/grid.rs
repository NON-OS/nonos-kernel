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

use crate::graphics::framebuffer::{put_pixel, fill_rect};
use crate::graphics::backgrounds::{get_background, is_using_wallpaper, get_cached_wallpaper};
use super::constants::{MENU_BAR_HEIGHT, DOCK_HEIGHT, SIDEBAR_WIDTH};
use super::grid_wallpaper::{draw_wallpaper_fullscreen, draw_image_background_fullscreen};

const COLOR_GRID_LINE: u32 = 0xFF0D1218;

pub(super) fn draw(w: u32, h: u32) {
    if is_using_wallpaper() {
        if let Some(wallpaper) = get_cached_wallpaper() {
            draw_wallpaper_fullscreen(w, h, wallpaper.width, wallpaper.height, wallpaper.pixels.as_slice());
            return;
        }
    }

    let bg = get_background();
    if let Some(pixels) = bg.pixels() {
        draw_image_background_fullscreen(w, h, pixels);
    } else {
        let top = MENU_BAR_HEIGHT;
        let bottom = h - DOCK_HEIGHT;
        let left = SIDEBAR_WIDTH;

        draw_gradient(left, top, w - left, bottom - top);

        draw_minimal_grid(left, top, w, bottom);
    }
}

fn draw_gradient(x: u32, y: u32, width: u32, height: u32) {
    let bg = get_background();
    let (top_color, bottom_color) = bg.gradient_colors();

    let top_r = ((top_color >> 16) & 0xFF) as u32;
    let top_g = ((top_color >> 8) & 0xFF) as u32;
    let top_b = (top_color & 0xFF) as u32;

    let bot_r = ((bottom_color >> 16) & 0xFF) as u32;
    let bot_g = ((bottom_color >> 8) & 0xFF) as u32;
    let bot_b = (bottom_color & 0xFF) as u32;

    for row in 0..height {
        let t = (row * 256) / height;

        let r = top_r + ((bot_r as i32 - top_r as i32) * t as i32 / 256) as u32;
        let g = top_g + ((bot_g as i32 - top_g as i32) * t as i32 / 256) as u32;
        let b = top_b + ((bot_b as i32 - top_b as i32) * t as i32 / 256) as u32;

        let color = 0xFF000000 | (r.min(255) << 16) | (g.min(255) << 8) | b.min(255);
        fill_rect(x, y + row, width, 1, color);
    }

    if bg.has_pattern() {
        draw_cyber_grid_pattern(x, y, width, height);
    }
}

fn draw_minimal_grid(left: u32, top: u32, w: u32, bottom: u32) {
    let spacing = 60u32;

    let mut x = left + spacing;
    while x < w {
        for y in top..bottom {
            if y % 4 < 1 {
                put_pixel(x, y, COLOR_GRID_LINE);
            }
        }
        x += spacing;
    }

    let mut y = top + spacing;
    while y < bottom {
        for x in left..w {
            if x % 4 < 1 {
                put_pixel(x, y, COLOR_GRID_LINE);
            }
        }
        y += spacing;
    }
}

fn draw_cyber_grid_pattern(x: u32, y: u32, width: u32, height: u32) {
    let spacing = 40u32;
    let line_color = 0xFF1A1A3A;

    let mut row = 0u32;
    let mut line_y = y;
    while line_y < y + height {
        for px in x..x + width {
            if (px - x) % 2 == 0 {
                put_pixel(px, line_y, line_color);
            }
        }
        row += 1;
        let perspective_space = spacing + (row * 2).min(spacing);
        line_y += perspective_space;
    }

    let center_x = x + width / 2;
    let horizon_y = y;
    let bottom_y = y + height;

    for i in 0..12 {
        let offset = i as i32 * (width as i32 / 12);

        let start_x = center_x as i32 - offset / 2;
        let end_x = (center_x as i32 - offset).max(x as i32);

        for py in horizon_y..bottom_y {
            let t = ((py - horizon_y) as i32 * 256) / (bottom_y - horizon_y) as i32;
            let px = start_x + ((end_x - start_x) * t) / 256;
            if px >= x as i32 && px < (x + width) as i32 && py % 2 == 0 {
                put_pixel(px as u32, py, line_color);
            }
        }

        let start_x = center_x as i32 + offset / 2;
        let end_x = (center_x as i32 + offset).min((x + width) as i32);

        for py in horizon_y..bottom_y {
            let t = ((py - horizon_y) as i32 * 256) / (bottom_y - horizon_y) as i32;
            let px = start_x + ((end_x - start_x) * t) / 256;
            if px >= x as i32 && px < (x + width) as i32 && py % 2 == 0 {
                put_pixel(px as u32, py, line_color);
            }
        }
    }
}
