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

use super::state::{get_category, PREVIEW_HEIGHT, PREVIEW_WIDTH};
use crate::graphics::backgrounds::{
    get_cached_wallpaper, get_current_wallpaper_id, get_wallpapers_by_category,
    WallpaperCategory,
};
use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_ACCENT, COLOR_TEXT_WHITE};
use crate::graphics::themes::get_theme;
use crate::graphics::window::settings::render::draw_string;

pub fn draw(x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, 350, 0xFF1C2128);

    draw_theme_section(x, y, w);

    let bg_start_y = y + 80;
    draw_string(x + 15, bg_start_y, b"Desktop Background", COLOR_TEXT_WHITE);

    let content_y = bg_start_y + 25;
    draw_wallpapers(x, content_y, w);
}

fn draw_theme_section(x: u32, y: u32, w: u32) {
    let current = get_theme();

    draw_string(x + 15, y + 10, b"Color Theme", COLOR_TEXT_WHITE);
    fill_rect(x + 15, y + 30, w - 30, 36, 0xFF1A1F26);

    fill_rect(x + 20, y + 35, 26, 26, 0xFF2D333B);
    draw_string(x + 28, y + 40, b"<", COLOR_TEXT_WHITE);

    for (i, ch) in current.name().bytes().enumerate() {
        crate::graphics::font::draw_char(x + 60 + (i as u32) * 8, y + 41, ch, COLOR_TEXT_WHITE);
    }

    let colors = current.colors();
    let swatch_x = x + 200;
    let swatch_y = y + 37;

    fill_rect(swatch_x, swatch_y, 20, 20, colors.bg_primary);
    fill_rect(swatch_x + 22, swatch_y, 20, 20, colors.bg_secondary);
    fill_rect(swatch_x + 44, swatch_y, 20, 20, colors.accent);
    fill_rect(swatch_x + 66, swatch_y, 20, 20, colors.success);
    fill_rect(swatch_x + 88, swatch_y, 20, 20, colors.error);

    fill_rect(x + w - 46, y + 35, 26, 26, 0xFF2D333B);
    draw_string(x + w - 38, y + 40, b">", COLOR_TEXT_WHITE);
}

fn draw_wallpapers(x: u32, y: u32, w: u32) {
    draw_category_tabs(x, y, w);

    let content_y = y + 35;
    draw_string(x + 15, content_y, b"Select a wallpaper", 0xFF7D8590);

    let current_category = WallpaperCategory::from_u8(get_category());
    let wallpapers = get_wallpapers_by_category(current_category);
    let current_wallpaper_id = get_current_wallpaper_id();

    let start_y = content_y + 25;
    let cols = (w - 40) / (PREVIEW_WIDTH + 15);

    for (i, wallpaper) in wallpapers.iter().enumerate() {
        let col = (i as u32) % cols;
        let row = (i as u32) / cols;
        let px = x + 20 + col * (PREVIEW_WIDTH + 15);
        let py = start_y + row * (PREVIEW_HEIGHT + 30);

        let is_selected = current_wallpaper_id == wallpaper.id as usize;

        if is_selected {
            fill_rect(px - 2, py - 2, PREVIEW_WIDTH + 4, PREVIEW_HEIGHT + 4, COLOR_ACCENT);
        } else {
            fill_rect(px - 1, py - 1, PREVIEW_WIDTH + 2, PREVIEW_HEIGHT + 2, 0xFF30363D);
        }

        draw_wallpaper_preview(px, py, PREVIEW_WIDTH, PREVIEW_HEIGHT, wallpaper.id, is_selected, current_category);

        let name_color = if is_selected { COLOR_TEXT_WHITE } else { 0xFF7D8590 };
        draw_truncated_name(px, py + PREVIEW_HEIGHT + 5, wallpaper.name, name_color);
    }
}

fn draw_category_tabs(x: u32, y: u32, w: u32) {
    let current = get_category();
    let categories = WallpaperCategory::all();
    let tab_w = (w - 30) / 4;

    for (i, cat) in categories.iter().enumerate() {
        let tab_x = x + 15 + (i as u32) * (tab_w + 2);
        let is_selected = current == i as u8;

        let bg_color = if is_selected { 0xFF1F6FEB } else { 0xFF21262D };
        fill_rect(tab_x, y, tab_w, 24, bg_color);

        let name = cat.short_name();
        let text_x = tab_x + (tab_w - (name.len() as u32 * 8)) / 2;
        draw_string(text_x, y + 6, name.as_bytes(), COLOR_TEXT_WHITE);
    }
}

fn draw_wallpaper_preview(x: u32, y: u32, w: u32, h: u32, _id: u8, is_current: bool, category: WallpaperCategory) {
    if is_current {
        if let Some(img) = get_cached_wallpaper() {
            img.draw_scaled(x, y, w, h);
            return;
        }
    }

    match category {
        WallpaperCategory::NetworkTopology => {
            fill_rect(x, y, w, h, 0xFF0A1628);
            let node_positions = [
                (15, 12), (45, 18), (65, 10), (25, 35), (55, 32), (40, 25)
            ];
            for (nx, ny) in node_positions.iter() {
                if *nx < w && *ny < h {
                    for dy in 0..4u32 {
                        for dx in 0..4u32 {
                            if (dx as i32 - 1) * (dx as i32 - 1) + (dy as i32 - 1) * (dy as i32 - 1) <= 3 {
                                put_pixel(x + nx + dx, y + ny + dy, 0xFF00D4FF);
                            }
                        }
                    }
                }
            }
            for i in 0..node_positions.len() - 1 {
                let (x1, y1) = node_positions[i];
                let (x2, y2) = node_positions[i + 1];
                draw_line(x + x1 + 2, y + y1 + 2, x + x2 + 2, y + y2 + 2, 0xFF1A4A6A);
            }
        }
        WallpaperCategory::FieldFocus => {
            fill_rect(x, y, w, h / 4, 0xFF101018);
            fill_rect(x, y + h / 4, w, h / 4, 0xFF181020);
            fill_rect(x, y + h / 2, w, h / 4, 0xFF201828);
            fill_rect(x, y + 3 * h / 4, w, h - 3 * h / 4, 0xFF282030);
            let bokeh = [(20, 15, 6), (50, 25, 5), (65, 40, 8), (30, 38, 4)];
            for (bx, by, br) in bokeh.iter() {
                if *bx + *br < w && *by + *br < h {
                    fill_rect(x + bx - 1, y + by, *br + 2, 1, 0x40FFFFFF);
                    fill_rect(x + bx - 1, y + by + *br, *br + 2, 1, 0x40FFFFFF);
                    fill_rect(x + bx, y + by, 1, *br, 0x40FFFFFF);
                    fill_rect(x + bx + *br, y + by, 1, *br, 0x40FFFFFF);
                }
            }
        }
        WallpaperCategory::HardwareAesthetic => {
            fill_rect(x, y, w, h, 0xFF0D1117);
            let traces = [
                (5, 10, 35, 10), (35, 10, 35, 30), (35, 30, 60, 30),
                (10, 25, 25, 25), (25, 25, 25, 40), (50, 15, 70, 15),
            ];
            for (x1, y1, x2, y2) in traces.iter() {
                if *x1 < w && *y1 < h && *x2 < w && *y2 < h {
                    if *x1 == *x2 {
                        fill_rect(x + x1, y + (*y1).min(*y2), 2, (*y2 as i32 - *y1 as i32).abs() as u32 + 1, 0xFF1A4A3A);
                    } else {
                        fill_rect(x + (*x1).min(*x2), y + y1, (*x2 as i32 - *x1 as i32).abs() as u32 + 1, 2, 0xFF1A4A3A);
                    }
                }
            }
            fill_rect(x + 30, y + 18, 16, 12, 0xFF2A3A4A);
            fill_rect(x + 33, y + 21, 10, 6, 0xFF00AA66);
        }
        WallpaperCategory::SpecialVariants => {
            fill_rect(x, y, w, h / 3, 0xFF0A0E14);
            fill_rect(x, y + h / 3, w, h / 3, 0xFF101820);
            fill_rect(x, y + 2 * h / 3, w, h - 2 * h / 3, 0xFF182028);
            let cx = x + w / 2;
            let cy = y + h / 2;
            fill_rect(cx - 12, cy - 8, 24, 16, 0x2000D4FF);
            fill_rect(cx - 8, cy - 5, 16, 10, 0x3000D4FF);
            fill_rect(cx - 4, cy - 3, 8, 6, 0x4000D4FF);
        }
    }
}

fn draw_line(x1: u32, y1: u32, x2: u32, y2: u32, color: u32) {
    let dx = (x2 as i32 - x1 as i32).abs();
    let dy = (y2 as i32 - y1 as i32).abs();
    let sx: i32 = if x1 < x2 { 1 } else { -1 };
    let sy: i32 = if y1 < y2 { 1 } else { -1 };
    let mut err = dx - dy;

    let mut cx = x1 as i32;
    let mut cy = y1 as i32;

    loop {
        if cx >= 0 && cy >= 0 {
            put_pixel(cx as u32, cy as u32, color);
        }

        if cx == x2 as i32 && cy == y2 as i32 {
            break;
        }

        let e2 = 2 * err;
        if e2 > -dy {
            err -= dy;
            cx += sx;
        }
        if e2 < dx {
            err += dx;
            cy += sy;
        }
    }
}

fn draw_truncated_name(x: u32, y: u32, name: &str, color: u32) {
    let name_bytes = name.as_bytes();
    let max_chars = (PREVIEW_WIDTH / 8) as usize;

    if name_bytes.len() <= max_chars {
        draw_string(x, y, name_bytes, color);
    } else {
        draw_string(x, y, &name_bytes[..max_chars - 2], color);
        draw_string(x + ((max_chars - 2) as u32 * 8), y, b"..", color);
    }
}
