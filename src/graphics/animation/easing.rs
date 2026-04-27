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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Easing {
    Linear,
    EaseIn,
    EaseOut,
    EaseInOut,
    Spring,
}

pub fn apply_easing(t: f32, easing: Easing) -> f32 {
    let t = t.clamp(0.0, 1.0);
    match easing {
        Easing::Linear => t,
        Easing::EaseIn => ease_in_cubic(t),
        Easing::EaseOut => ease_out_cubic(t),
        Easing::EaseInOut => ease_in_out_cubic(t),
        Easing::Spring => spring_ease(t),
    }
}

fn ease_in_cubic(t: f32) -> f32 {
    t * t * t
}
fn ease_out_cubic(t: f32) -> f32 {
    let t = 1.0 - t;
    1.0 - t * t * t
}
fn ease_in_out_cubic(t: f32) -> f32 {
    if t < 0.5 {
        4.0 * t * t * t
    } else {
        let v = -2.0 * t + 2.0;
        1.0 - (v * v * v) / 2.0
    }
}

fn spring_ease(t: f32) -> f32 {
    const C4: f32 = 6.283185 / 3.0;
    if t <= 0.0 {
        return 0.0;
    }
    if t >= 1.0 {
        return 1.0;
    }
    let pow = libm::powf(2.0, -10.0 * t);
    let sin_val = libm::sinf((t * 10.0 - 0.75) * C4);
    pow * sin_val + 1.0
}

pub fn interpolate(start: f32, end: f32, progress: f32) -> f32 {
    start + (end - start) * progress
}

pub fn interpolate_u32(start: u32, end: u32, progress: f32) -> u32 {
    if progress <= 0.0 {
        return start;
    }
    if progress >= 1.0 {
        return end;
    }
    let diff = end as f32 - start as f32;
    (start as f32 + diff * progress) as u32
}

pub fn interpolate_color(start: u32, end: u32, progress: f32) -> u32 {
    let sa = (start >> 24) & 0xFF;
    let sr = (start >> 16) & 0xFF;
    let sg = (start >> 8) & 0xFF;
    let sb = start & 0xFF;
    let ea = (end >> 24) & 0xFF;
    let er = (end >> 16) & 0xFF;
    let eg = (end >> 8) & 0xFF;
    let eb = end & 0xFF;
    let a = interpolate_u32(sa, ea, progress);
    let r = interpolate_u32(sr, er, progress);
    let g = interpolate_u32(sg, eg, progress);
    let b = interpolate_u32(sb, eb, progress);
    (a << 24) | (r << 16) | (g << 8) | b
}
