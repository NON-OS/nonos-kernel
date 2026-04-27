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

use super::{Animation, Easing};

pub fn fade_in(duration_ms: u64) -> Animation {
    Animation::new(0.0, 1.0, duration_ms, Easing::EaseOut)
}
pub fn fade_out(duration_ms: u64) -> Animation {
    Animation::new(1.0, 0.0, duration_ms, Easing::EaseIn)
}

pub fn slide_in_left(width: f32, duration_ms: u64) -> Animation {
    Animation::new(-width, 0.0, duration_ms, Easing::EaseOut)
}

pub fn slide_in_right(width: f32, duration_ms: u64) -> Animation {
    Animation::new(width, 0.0, duration_ms, Easing::EaseOut)
}

pub fn slide_in_up(height: f32, duration_ms: u64) -> Animation {
    Animation::new(height, 0.0, duration_ms, Easing::EaseOut)
}

pub fn slide_in_down(height: f32, duration_ms: u64) -> Animation {
    Animation::new(-height, 0.0, duration_ms, Easing::EaseOut)
}

pub fn scale_in(duration_ms: u64) -> Animation {
    Animation::new(0.0, 1.0, duration_ms, Easing::Spring)
}
pub fn scale_out(duration_ms: u64) -> Animation {
    Animation::new(1.0, 0.0, duration_ms, Easing::EaseIn)
}

pub fn bounce(duration_ms: u64) -> Animation {
    Animation::new(0.0, 1.0, duration_ms, Easing::Spring)
}

pub fn hover_grow(duration_ms: u64) -> Animation {
    Animation::new(1.0, 1.05, duration_ms, Easing::EaseOut)
}
pub fn hover_shrink(duration_ms: u64) -> Animation {
    Animation::new(1.05, 1.0, duration_ms, Easing::EaseOut)
}

pub fn press(duration_ms: u64) -> Animation {
    Animation::new(1.0, 0.95, duration_ms, Easing::EaseOut)
}
pub fn release(duration_ms: u64) -> Animation {
    Animation::new(0.95, 1.0, duration_ms, Easing::Spring)
}

pub fn pulse_glow(duration_ms: u64) -> Animation {
    Animation::new(0.6, 1.0, duration_ms, Easing::EaseInOut)
}

pub fn spinner_rotation(duration_ms: u64) -> Animation {
    Animation::new(0.0, 360.0, duration_ms, Easing::Linear)
}

pub const DURATION_FAST: u64 = 150;
pub const DURATION_NORMAL: u64 = 250;
pub const DURATION_SLOW: u64 = 400;
pub const DURATION_VERY_SLOW: u64 = 600;
