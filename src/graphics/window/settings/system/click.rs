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

use super::click2::{handle_dark_theme, handle_keyboard};
use super::click3::{handle_language, handle_screen_timeout, handle_timezone};
use crate::sys::settings as sys_settings;

pub(crate) fn handle_click(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    if handle_brightness(cx, cy, cw, mx, my) {
        return true;
    }
    if handle_mouse_speed(cx, cy, cw, mx, my) {
        return true;
    }
    if handle_sound(cx, cy, cw, mx, my) {
        return true;
    }
    if handle_notifications(cx, cy, cw, mx, my) {
        return true;
    }
    if handle_keyboard(cx, cy, mx, my) {
        return true;
    }
    if handle_dark_theme(cx, cy, cw, mx, my) {
        return true;
    }
    if handle_timezone(cx, cy, cw, mx, my) {
        return true;
    }
    if handle_screen_timeout(cx, cy, mx, my) {
        return true;
    }
    if handle_language(cx, cy, mx, my) {
        return true;
    }
    false
}

fn handle_notifications(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let toggle_x = cx + cw - 70;
    let toggle_y = cy + 166;
    if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
        if my >= toggle_y as i32 && my < (toggle_y + 26) as i32 {
            sys_settings::set_notifications_enabled(!sys_settings::notifications_enabled());
            return true;
        }
    }
    false
}

fn handle_brightness(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let slider_y = cy + 52;
    if my >= slider_y as i32 && my < (slider_y + 20) as i32 {
        let rel_x = mx - cx as i32 - 28;
        if rel_x >= 0 && rel_x < (cw - 72) as i32 {
            let new_val = ((rel_x as u32) * 100 / (cw - 72)).min(100) as u8;
            sys_settings::set_brightness(new_val);
            return true;
        }
    }
    false
}

fn handle_mouse_speed(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let slider_y = cy + 94;
    if my >= slider_y as i32 && my < (slider_y + 20) as i32 {
        let rel_x = mx - cx as i32 - 28;
        if rel_x >= 0 && rel_x < (cw - 72) as i32 {
            let new_val = (((rel_x as u32) * 10 / (cw - 72)) + 1).min(10) as u8;
            sys_settings::set_mouse_sensitivity(new_val);
            return true;
        }
    }
    false
}

fn handle_sound(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let toggle_x = cx + cw - 70;
    let toggle_y = cy + 138;
    if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
        if my >= toggle_y as i32 && my < (toggle_y + 26) as i32 {
            sys_settings::set_sound_enabled(!sys_settings::sound_enabled());
            return true;
        }
    }
    false
}
