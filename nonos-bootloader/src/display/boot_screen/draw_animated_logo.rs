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

use crate::display::gop::fill_rect;
use crate::display::font::draw_string;
use crate::display::constants::COLOR_TEXT_WHITE;
use super::math_utils::{sin_approx, cos_approx};

static mut LOGO_FRAME: u16 = 0;

pub fn draw_animated_logo(center_x: u32, center_y: u32) {
    unsafe { LOGO_FRAME = (LOGO_FRAME + 1) % 360; }

    let primary_color = 0xFF00E5FFu32;
    let accent_color = 0xFFFF6D00u32;

    let pulse = (sin_approx(unsafe { LOGO_FRAME } as f32 * 0.1) * 20.0) as u32;
    let glow_size = 40 + pulse;

    fill_rect(center_x - glow_size/2, center_y - glow_size/2, glow_size, glow_size, primary_color);

    for i in 0..6 {
        let angle = unsafe { LOGO_FRAME } as f32 * 0.05 + i as f32 * 1.047;
        let orbit_x = (center_x as f32 + cos_approx(angle) * 60.0) as u32;
        let orbit_y = (center_y as f32 + sin_approx(angle) * 60.0) as u32;
        let dot_size = (6.0 + sin_approx(angle) * 3.0) as u32;

        fill_rect(orbit_x - dot_size/2, orbit_y - dot_size/2, dot_size, dot_size, accent_color);
    }

    draw_string(center_x - 24, center_y + 80, b"NONOS", COLOR_TEXT_WHITE);
    draw_string(center_x - 88, center_y + 120, b"Zero-State Microkernel", primary_color);
}