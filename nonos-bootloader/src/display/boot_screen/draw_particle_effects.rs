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
use super::math_utils::sin_approx;

static mut PARTICLE_TIMER: u32 = 0;

pub fn draw_particle_effects(width: u32, height: u32) {
    unsafe { PARTICLE_TIMER = PARTICLE_TIMER.wrapping_add(1); }

    for i in 0..80 {
        let x = ((i * 17 + unsafe { PARTICLE_TIMER } * 2) % width) as u32;
        let y = ((i * 23 + unsafe { PARTICLE_TIMER }) % height) as u32;
        let brightness_val = sin_approx(unsafe { PARTICLE_TIMER } as f32 * 0.01 + i as f32 * 0.1);
        let brightness = (brightness_val.abs() * 150.0) as u32;

        if brightness > 60 {
            let r = brightness / 6;
            let g = brightness / 3;
            let b = brightness;
            let color = 0xFF000000 | (r << 16) | (g << 8) | b;
            fill_rect(x, y, 1, 1, color);
        }
    }
}