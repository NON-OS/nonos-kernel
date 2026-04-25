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

use crate::graphics::window::settings::state::{toggle_setting, SETTING_DARK_THEME};
use crate::sys::settings as sys_settings;

pub(super) fn handle_keyboard(cx: u32, cy: u32, mx: i32, my: i32) -> bool {
    let row_y = cy + 282;
    let btn_spacing = 52i32;
    let btn_w = 48i32;
    let rel_x = mx - cx as i32 - 28;
    if rel_x >= 0 && my >= row_y as i32 && my < (row_y + 26) as i32 {
        let btn_idx = rel_x / btn_spacing;
        let in_button = (rel_x % btn_spacing) < btn_w;
        if in_button && btn_idx < 5 {
            sys_settings::set_keyboard_layout(btn_idx as u8);
            return true;
        }
    }
    false
}

pub(super) fn handle_dark_theme(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let toggle_x = cx + cw - 70;
    let dark_y = cy + 194;
    if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
        if my >= dark_y as i32 && my < (dark_y + 26) as i32 {
            toggle_setting(&SETTING_DARK_THEME);
            let is_dark = SETTING_DARK_THEME.load(core::sync::atomic::Ordering::Relaxed);
            sys_settings::set_theme(if is_dark { 0 } else { 1 });
            return true;
        }
    }
    false
}
