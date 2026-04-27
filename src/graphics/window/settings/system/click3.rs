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

use super::timezone::idx_to_timeout;
use crate::locale::{set_lang, Language};
use crate::sys::settings as sys_settings;

pub(super) fn handle_timezone(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let tz_y = cy + 355;
    let prev_x = cx + 33;
    if mx >= prev_x as i32 && mx < (prev_x + 26) as i32 {
        if my >= tz_y as i32 && my < (tz_y + 26) as i32 {
            let current = sys_settings::timezone();
            sys_settings::set_timezone(if current > -12 { current - 1 } else { 14 });
            return true;
        }
    }
    let next_x = cx + cw - 59;
    if mx >= next_x as i32 && mx < (next_x + 26) as i32 {
        if my >= tz_y as i32 && my < (tz_y + 26) as i32 {
            let current = sys_settings::timezone();
            sys_settings::set_timezone(if current < 14 { current + 1 } else { -12 });
            return true;
        }
    }
    false
}

pub(super) fn handle_screen_timeout(cx: u32, cy: u32, mx: i32, my: i32) -> bool {
    let timeout_y = cy + 490;
    if my >= timeout_y as i32 && my < (timeout_y + 26) as i32 {
        let rel_x = mx - cx as i32 - 28;
        if rel_x >= 0 {
            let btn_idx = (rel_x / 61) as u8;
            if btn_idx < 5 {
                sys_settings::set_screen_timeout(idx_to_timeout(btn_idx));
                return true;
            }
        }
    }
    false
}

pub(super) fn handle_language(cx: u32, cy: u32, mx: i32, my: i32) -> bool {
    let lang_y = cy + 432;
    if my >= lang_y as i32 && my < (lang_y + 26) as i32 {
        let rel_x = mx - cx as i32 - 28;
        if rel_x >= 0 {
            let btn_idx = (rel_x / 40) as u8;
            if btn_idx < 6 {
                set_lang(Language::from(btn_idx));
                return true;
            }
        }
    }
    false
}
