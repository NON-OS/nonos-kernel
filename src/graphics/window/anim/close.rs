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

use super::state::{add_animation, AnimationType, WindowAnimation};
use crate::graphics::animation::Easing;
use crate::time::timestamp_millis;

const CLOSE_DURATION_MS: u64 = 180;

pub fn start_close(window_id: u32, x: i32, y: i32, w: u32, h: u32) {
    let scale_end = 0.9f32;
    let center_x = x + (w as i32 / 2);
    let center_y = y + (h as i32 / 2);
    let end_w = (w as f32 * scale_end) as u32;
    let end_h = (h as f32 * scale_end) as u32;
    let end_x = center_x - (end_w as i32 / 2);
    let end_y = center_y - (end_h as i32 / 2);

    let anim = WindowAnimation {
        window_id,
        anim_type: AnimationType::Close,
        start_time: timestamp_millis(),
        duration_ms: CLOSE_DURATION_MS,
        easing: Easing::EaseIn,
        start_x: x,
        start_y: y,
        start_w: w,
        start_h: h,
        end_x,
        end_y,
        end_w,
        end_h,
        start_alpha: 1.0,
        end_alpha: 0.0,
        active: true,
    };
    add_animation(anim);
}
