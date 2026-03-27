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

use crate::graphics::backgrounds::{next_background, prev_background};
use crate::sys::settings as sys_settings;
use crate::graphics::window::settings::state::{toggle_setting, SETTING_DARK_THEME};
use super::state::set_background_changed;

pub(super) fn handle_keyboard(cx: u32, cy: u32, mx: i32, my: i32) -> bool {
    let layout_y = cy + 170;
    if my >= layout_y as i32 && my < (layout_y + 26) as i32 {
        let rel_x = mx - cx as i32 - 15;
        if rel_x >= 0 {
            let btn_idx = (rel_x / 58) as u8;
            if btn_idx < 4 {
                sys_settings::set_keyboard_layout(btn_idx);
                return true;
            }
        }
    }
    false
}

pub(super) fn handle_dark_theme(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let toggle_x = cx + cw - 70;
    let dark_y = cy + 205;
    if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
        if my >= dark_y as i32 && my < (dark_y + 26) as i32 {
            toggle_setting(&SETTING_DARK_THEME);
            return true;
        }
    }
    false
}

pub(super) fn handle_background(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let bg_button_y = cy + 275;
    let prev_x = cx + 20;
    if mx >= prev_x as i32 && mx < (prev_x + 26) as i32 {
        if my >= bg_button_y as i32 && my < (bg_button_y + 26) as i32 {
            prev_background();
            set_background_changed();
            return true;
        }
    }
    let next_x = cx + cw - 46;
    if mx >= next_x as i32 && mx < (next_x + 26) as i32 {
        if my >= bg_button_y as i32 && my < (bg_button_y + 26) as i32 {
            next_background();
            set_background_changed();
            return true;
        }
    }
    false
}
