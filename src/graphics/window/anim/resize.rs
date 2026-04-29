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

const RESIZE_DURATION_MS: u64 = 200;

pub fn start_resize(
    window_id: u32,
    from_x: i32,
    from_y: i32,
    from_w: u32,
    from_h: u32,
    to_x: i32,
    to_y: i32,
    to_w: u32,
    to_h: u32,
) {
    let anim = WindowAnimation {
        window_id,
        anim_type: AnimationType::Resize,
        start_time: timestamp_millis(),
        duration_ms: RESIZE_DURATION_MS,
        easing: Easing::EaseOut,
        start_x: from_x,
        start_y: from_y,
        start_w: from_w,
        start_h: from_h,
        end_x: to_x,
        end_y: to_y,
        end_w: to_w,
        end_h: to_h,
        start_alpha: 1.0,
        end_alpha: 1.0,
        active: true,
    };
    add_animation(anim);
}
