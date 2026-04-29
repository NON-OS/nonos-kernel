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
use crate::graphics::framebuffer::dimensions;
use crate::time::timestamp_millis;

const MINIMIZE_DURATION_MS: u64 = 300;
const DOCK_HEIGHT: u32 = 64;
const DOCK_ICON_SIZE: u32 = 48;

pub fn start_minimize(window_id: u32, x: i32, y: i32, w: u32, h: u32, dock_slot: u32) {
    let (sw, sh) = dimensions();
    let dock_y = (sh - DOCK_HEIGHT + 8) as i32;
    let dock_x = (sw / 2 - 200 + dock_slot * 56) as i32;

    let anim = WindowAnimation {
        window_id,
        anim_type: AnimationType::Minimize,
        start_time: timestamp_millis(),
        duration_ms: MINIMIZE_DURATION_MS,
        easing: Easing::EaseInOut,
        start_x: x,
        start_y: y,
        start_w: w,
        start_h: h,
        end_x: dock_x,
        end_y: dock_y,
        end_w: DOCK_ICON_SIZE,
        end_h: DOCK_ICON_SIZE,
        start_alpha: 1.0,
        end_alpha: 0.0,
        active: true,
    };
    add_animation(anim);
}

pub fn start_restore(window_id: u32, target_x: i32, target_y: i32, target_w: u32, target_h: u32, dock_slot: u32) {
    let (sw, sh) = dimensions();
    let dock_y = (sh - DOCK_HEIGHT + 8) as i32;
    let dock_x = (sw / 2 - 200 + dock_slot * 56) as i32;

    let anim = WindowAnimation {
        window_id,
        anim_type: AnimationType::Restore,
        start_time: timestamp_millis(),
        duration_ms: MINIMIZE_DURATION_MS,
        easing: Easing::EaseOut,
        start_x: dock_x,
        start_y: dock_y,
        start_w: DOCK_ICON_SIZE,
        start_h: DOCK_ICON_SIZE,
        end_x: target_x,
        end_y: target_y,
        end_w: target_w,
        end_h: target_h,
        start_alpha: 0.0,
        end_alpha: 1.0,
        active: true,
    };
    add_animation(anim);
}
