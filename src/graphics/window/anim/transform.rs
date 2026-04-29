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

use super::state::WindowAnimation;

pub struct WindowTransform {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
    pub alpha: f32,
}

pub fn apply_transform(anim: &WindowAnimation) -> WindowTransform {
    let p = anim.progress();
    let x = lerp_i32(anim.start_x, anim.end_x, p);
    let y = lerp_i32(anim.start_y, anim.end_y, p);
    let w = lerp_u32(anim.start_w, anim.end_w, p);
    let h = lerp_u32(anim.start_h, anim.end_h, p);
    let alpha = lerp_f32(anim.start_alpha, anim.end_alpha, p);
    WindowTransform { x, y, w, h, alpha }
}

fn lerp_i32(start: i32, end: i32, t: f32) -> i32 {
    (start as f32 + (end - start) as f32 * t) as i32
}

fn lerp_u32(start: u32, end: u32, t: f32) -> u32 {
    let s = start as f32;
    let e = end as f32;
    (s + (e - s) * t) as u32
}

fn lerp_f32(start: f32, end: f32, t: f32) -> f32 {
    start + (end - start) * t
}
