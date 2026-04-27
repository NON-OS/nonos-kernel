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

use crate::sys::settings as sys_settings;

pub(super) fn handle_wifi(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let toggle_x = cx + cw - 70;
    let wifi_y = cy + 232;
    if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
        if my >= wifi_y as i32 && my < (wifi_y + 26) as i32 {
            let curr = sys_settings::wifi_autoconnect();
            sys_settings::set_wifi_autoconnect(!curr);
            return true;
        }
    }
    false
}

pub(super) fn handle_autolock(cx: u32, cy: u32, mx: i32, my: i32) -> bool {
    let lock_y = cy + 268;
    if my >= lock_y as i32 && my < (lock_y + 24) as i32 {
        let rel_x = mx - cx as i32 - 128;
        if rel_x >= 0 {
            let btn_idx = rel_x / 40;
            if btn_idx < 4 {
                let val = match btn_idx {
                    0 => 0,
                    1 => 1,
                    2 => 5,
                    _ => 15,
                };
                sys_settings::set_auto_lock_timeout(val);
                return true;
            }
        }
    }
    false
}

pub(super) fn handle_data(cx: u32, cy: u32, mx: i32, my: i32) -> bool {
    let clear_y = cy + 340;
    if my >= clear_y as i32 && my < (clear_y + 32) as i32 {
        if mx >= (cx + 28) as i32 && mx < (cx + 155) as i32 {
            crate::network::http_client::clear_all_cookies();
            return true;
        }
        if mx >= (cx + 165) as i32 && mx < (cx + 305) as i32 {
            crate::apps::ecosystem::browser::history::clear_history();
            return true;
        }
    }
    false
}
