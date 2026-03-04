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

use crate::graphics::framebuffer::put_pixel;
use crate::graphics::backgrounds::{BG_WIDTH, BG_HEIGHT};

pub(super) fn draw_wallpaper_fullscreen(screen_w: u32, screen_h: u32, src_w: u32, src_h: u32, pixels: &[u32]) {
    let use_width_scale = (screen_w as u64) * (src_h as u64) > (screen_h as u64) * (src_w as u64);

    if use_width_scale {
        let effective_src_h = ((src_w as u64) * (screen_h as u64) / (screen_w as u64)) as u32;
        let crop_y = (src_h.saturating_sub(effective_src_h)) / 2;

        for dy in 0..screen_h {
            let src_y = crop_y + (dy as u64 * effective_src_h as u64 / screen_h as u64) as u32;
            if src_y >= src_h { continue; }

            let row_offset = (src_y as usize) * (src_w as usize);

            for dx in 0..screen_w {
                let src_x = (dx as u64 * src_w as u64 / screen_w as u64) as u32;
                if src_x >= src_w { continue; }

                let idx = row_offset + src_x as usize;
                if idx < pixels.len() {
                    put_pixel(dx, dy, pixels[idx]);
                }
            }
        }
    } else {
        let effective_src_w = ((src_h as u64) * (screen_w as u64) / (screen_h as u64)) as u32;
        let crop_x = (src_w.saturating_sub(effective_src_w)) / 2;

        for dy in 0..screen_h {
            let src_y = (dy as u64 * src_h as u64 / screen_h as u64) as u32;
            if src_y >= src_h { continue; }

            let row_offset = (src_y as usize) * (src_w as usize);

            for dx in 0..screen_w {
                let src_x = crop_x + (dx as u64 * effective_src_w as u64 / screen_w as u64) as u32;
                if src_x >= src_w { continue; }

                let idx = row_offset + src_x as usize;
                if idx < pixels.len() {
                    put_pixel(dx, dy, pixels[idx]);
                }
            }
        }
    }
}

pub(super) fn draw_image_background_fullscreen(screen_w: u32, screen_h: u32, pixels: &[u32]) {
    let src_w = BG_WIDTH;
    let src_h = BG_HEIGHT;

    let use_width_scale = (screen_w as u64) * (src_h as u64) > (screen_h as u64) * (src_w as u64);

    if use_width_scale {
        let effective_src_h = ((src_w as u64) * (screen_h as u64) / (screen_w as u64)) as u32;
        let crop_y = (src_h.saturating_sub(effective_src_h)) / 2;

        for dy in 0..screen_h {
            let src_y = crop_y + (dy as u64 * effective_src_h as u64 / screen_h as u64) as u32;
            if src_y >= src_h { continue; }

            let row_offset = (src_y as usize) * (src_w as usize);

            for dx in 0..screen_w {
                let src_x = (dx as u64 * src_w as u64 / screen_w as u64) as u32;
                if src_x >= src_w { continue; }

                let idx = row_offset + src_x as usize;
                if idx < pixels.len() {
                    put_pixel(dx, dy, pixels[idx]);
                }
            }
        }
    } else {
        let effective_src_w = ((src_h as u64) * (screen_w as u64) / (screen_h as u64)) as u32;
        let crop_x = (src_w.saturating_sub(effective_src_w)) / 2;

        for dy in 0..screen_h {
            let src_y = (dy as u64 * src_h as u64 / screen_h as u64) as u32;
            if src_y >= src_h { continue; }

            let row_offset = (src_y as usize) * (src_w as usize);

            for dx in 0..screen_w {
                let src_x = crop_x + (dx as u64 * effective_src_w as u64 / screen_w as u64) as u32;
                if src_x >= src_w { continue; }

                let idx = row_offset + src_x as usize;
                if idx < pixels.len() {
                    put_pixel(dx, dy, pixels[idx]);
                }
            }
        }
    }
}
