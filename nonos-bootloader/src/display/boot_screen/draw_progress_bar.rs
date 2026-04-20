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

use crate::graphics::framebuffer::{draw_filled_rect, draw_text};
use crate::graphics::colors::{RGB, WHITE};

static mut PROGRESS_PERCENT: f32 = 0.0;
static mut SHIMMER_POS: f32 = 0.0;

pub fn draw_progress_bar(x: u32, y: u32, width: u32, height: u32) {
    let bg_color = RGB { r: 0x2D, g: 0x3F, b: 0x4F };
    let fill_color = RGB { r: 0x00, g: 0xD4, b: 0x69 };
    let shimmer_color = RGB { r: 255, g: 255, b: 255 };

    draw_filled_rect(x, y, width, height, bg_color);

    let fill_width = (width as f32 * unsafe { PROGRESS_PERCENT } / 100.0) as u32;
    if fill_width > 0 {
        draw_filled_rect(x + 2, y + 2, fill_width - 4, height - 4, fill_color);

        unsafe { SHIMMER_POS += 2.0; }
        if unsafe { SHIMMER_POS } > width as f32 { unsafe { SHIMMER_POS = 0.0; } }

        let shimmer_x = x + unsafe { SHIMMER_POS } as u32;
        if shimmer_x < x + fill_width && shimmer_x + 20 > x {
            for i in 0..20 {
                let alpha = (255 * (20 - i) / 20) as u8;
                let color = RGB {
                    r: (shimmer_color.r as u16 * alpha as u16 / 255) as u8,
                    g: (shimmer_color.g as u16 * alpha as u16 / 255) as u8,
                    b: (shimmer_color.b as u16 * alpha as u16 / 255) as u8,
                };
                if shimmer_x + i < x + fill_width {
                    draw_filled_rect(shimmer_x + i, y + 2, 1, height - 4, color);
                }
            }
        }
    }

    let percentage_text = format!("{:.0}%", unsafe { PROGRESS_PERCENT });
    draw_text(x + width + 20, y + 8, &percentage_text, WHITE, 1);
}

pub fn set_progress_percent(percent: f32) {
    unsafe { PROGRESS_PERCENT = percent.max(0.0).min(100.0); }
}