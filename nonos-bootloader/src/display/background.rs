// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

/*
 * Background Image Renderer.
 *
 * Decodes RLE-compressed background image generated at build time.
 * Scales to screen resolution using nearest-neighbor for speed.
 * The field-focus-8.png provides that calm nature aesthetic.
 */

use super::gop::{get_dimensions, is_initialized, put_pixel};

include!(concat!(env!("OUT_DIR"), "/background_generated.rs"));

pub fn render_background() {
    if !is_initialized() {
        return;
    }

    let (screen_w, screen_h) = get_dimensions();
    if screen_w == 0 || screen_h == 0 {
        return;
    }

    render_scaled(screen_w, screen_h);
}

fn render_scaled(screen_w: u32, screen_h: u32) {

    /* Decode compressed data into temporary buffer */
    let total_pixels = (BG_WIDTH * BG_HEIGHT) as usize;
    let mut decoded: [u32; 640 * 360] = [0; 640 * 360];

    let mut src_idx = 0;
    let mut dst_idx = 0;

    while src_idx + 4 < BG_COMPRESSED_LEN && dst_idx < total_pixels {
        let run = BG_COMPRESSED[src_idx] as usize;
        let b = BG_COMPRESSED[src_idx + 1] as u32;
        let g = BG_COMPRESSED[src_idx + 2] as u32;
        let r = BG_COMPRESSED[src_idx + 3] as u32;
        let a = BG_COMPRESSED[src_idx + 4] as u32;

        let color = (a << 24) | (r << 16) | (g << 8) | b;

        for _ in 0..run {
            if dst_idx < total_pixels {
                decoded[dst_idx] = color;
                dst_idx += 1;
            }
        }

        src_idx += 5;
    }

    /* Scale to screen using nearest-neighbor */
    let scale_x = (BG_WIDTH << 16) / screen_w;
    let scale_y = (BG_HEIGHT << 16) / screen_h;

    for screen_y in 0..screen_h {
        let src_y = ((screen_y * scale_y) >> 16).min(BG_HEIGHT - 1);

        for screen_x in 0..screen_w {
            let src_x = ((screen_x * scale_x) >> 16).min(BG_WIDTH - 1);
            let src_idx = (src_y * BG_WIDTH + src_x) as usize;

            if src_idx < total_pixels {
                put_pixel(screen_x, screen_y, decoded[src_idx]);
            }
        }
    }
}

pub fn render_background_with_overlay(overlay_alpha: u8) {
    if !is_initialized() {
        return;
    }

    let (screen_w, screen_h) = get_dimensions();
    if screen_w == 0 || screen_h == 0 {
        return;
    }

    render_background();

    /* Apply dark overlay for text readability */
    if overlay_alpha > 0 {
        apply_dark_overlay(screen_w, screen_h, overlay_alpha);
    }
}

fn apply_dark_overlay(screen_w: u32, screen_h: u32, alpha: u8) {
    let overlay_color = blend_color(0xFF000000, alpha);

    for y in 0..screen_h {
        for x in 0..screen_w {
            put_pixel(x, y, overlay_color);
        }
    }
}

fn blend_color(color: u32, alpha: u8) -> u32 {
    let a = alpha as u32;
    let r = ((color >> 16) & 0xFF) * a / 255;
    let g = ((color >> 8) & 0xFF) * a / 255;
    let b = (color & 0xFF) * a / 255;

    (a << 24) | (r << 16) | (g << 8) | b
}
