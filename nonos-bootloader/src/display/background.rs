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
 * Decodes RLE row-by-row for fast rendering without stack overflow.
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
    let scale_x = (BG_WIDTH << 16) / screen_w;
    let scale_y = (BG_HEIGHT << 16) / screen_h;

    let mut decoder = RleDecoder::new();
    let mut cached_src_y: u32 = 0xFFFFFFFF;
    let mut row_buf: [u32; 640] = [0; 640];

    for screen_y in 0..screen_h {
        let src_y = ((screen_y * scale_y) >> 16).min(BG_HEIGHT - 1);

        if src_y != cached_src_y {
            decoder.decode_row(src_y, &mut row_buf);
            cached_src_y = src_y;
        }

        for screen_x in 0..screen_w {
            let src_x = ((screen_x * scale_x) >> 16).min(BG_WIDTH - 1);
            put_pixel(screen_x, screen_y, row_buf[src_x as usize]);
        }
    }
}

struct RleDecoder {
    src_idx: usize,
    pixel_idx: usize,
    current_run: u8,
    run_remaining: u8,
    current_color: u32,
}

impl RleDecoder {
    const fn new() -> Self {
        Self {
            src_idx: 0,
            pixel_idx: 0,
            current_run: 0,
            run_remaining: 0,
            current_color: 0xFF000000,
        }
    }

    fn decode_row(&mut self, row: u32, buf: &mut [u32; 640]) {
        let row_start = (row * BG_WIDTH) as usize;
        let row_end = row_start + BG_WIDTH as usize;

        if row_start < self.pixel_idx {
            self.reset();
        }

        while self.pixel_idx < row_start {
            self.advance_pixel();
        }

        for i in 0..BG_WIDTH as usize {
            if self.pixel_idx < row_end {
                buf[i] = self.current_color;
                self.advance_pixel();
            } else {
                buf[i] = 0xFF000000;
            }
        }
    }

    fn advance_pixel(&mut self) {
        if self.run_remaining > 0 {
            self.run_remaining -= 1;
            self.pixel_idx += 1;
            return;
        }

        if self.src_idx + 4 < BG_COMPRESSED_LEN {
            let run = BG_COMPRESSED[self.src_idx];
            let b = BG_COMPRESSED[self.src_idx + 1] as u32;
            let g = BG_COMPRESSED[self.src_idx + 2] as u32;
            let r = BG_COMPRESSED[self.src_idx + 3] as u32;
            let a = BG_COMPRESSED[self.src_idx + 4] as u32;

            self.current_color = (a << 24) | (r << 16) | (g << 8) | b;
            self.current_run = run;
            self.run_remaining = run.saturating_sub(1);
            self.src_idx += 5;
            self.pixel_idx += 1;
        }
    }

    fn reset(&mut self) {
        self.src_idx = 0;
        self.pixel_idx = 0;
        self.current_run = 0;
        self.run_remaining = 0;
        self.current_color = 0xFF000000;
    }
}
