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

use crate::graphics::window::settings::state::*;
use crate::sys::settings as sys_settings;

pub(crate) fn handle_click(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let toggle_x = cx + cw - 70;

    let btn_y = cy + 40;
    if my >= btn_y as i32 && my < (btn_y + 28) as i32 {
        let rel_x = mx - cx as i32 - 15;
        if rel_x >= 0 {
            let btn_idx = (rel_x / 83) as u8;
            if btn_idx < 4 {
                set_privacy_mode(btn_idx);
                return true;
            }
        }
    }

    let anyone_y = cy + 80;
    if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
        if my >= anyone_y as i32 && my < (anyone_y + 26) as i32 {
            let new_val = toggle_setting(&SETTING_NYM_ENABLED);
            sys_settings::set_nym_enabled(new_val);
            return true;
        }
    }

    let mac_y = cy + 135;
    if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
        if my >= mac_y as i32 && my < (mac_y + 26) as i32 {
            let new_val = toggle_setting(&SETTING_PRIVACY);
            sys_settings::set_anonymous_mode(new_val);
            return true;
        }
    }

    let zs_y = cy + 175;
    if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
        if my >= zs_y as i32 && my < (zs_y + 26) as i32 {
            let new_val = toggle_setting(&SETTING_ZERO_STATE);
            sys_settings::set_auto_wipe(new_val);
            return true;
        }
    }

    if super::click2::handle_wifi(cx, cy, cw, mx, my) {
        return true;
    }
    if super::click2::handle_autolock(cx, cy, mx, my) {
        return true;
    }
    super::click2::handle_data(cx, cy, mx, my)
}
