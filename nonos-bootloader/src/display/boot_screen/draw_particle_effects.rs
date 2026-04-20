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

use crate::graphics::framebuffer::draw_filled_rect;
use crate::graphics::colors::RGB;

static mut PARTICLE_TIMER: u32 = 0;

pub fn draw_particle_effects(width: u32, height: u32) {
    unsafe { PARTICLE_TIMER = PARTICLE_TIMER.wrapping_add(1); }

    for i in 0..80 {
        let x = ((i * 17 + unsafe { PARTICLE_TIMER } * 2) % width) as u32;
        let y = ((i * 23 + unsafe { PARTICLE_TIMER }) % height) as u32;
        let brightness = ((unsafe { PARTICLE_TIMER } as f32 * 0.01 + i as f32 * 0.1).sin().abs() * 150.0) as u8;

        if brightness > 60 {
            let color = RGB {
                r: brightness / 6,
                g: brightness / 3,
                b: brightness,
            };
            draw_filled_rect(x, y, 1, 1, color);
        }
    }
}