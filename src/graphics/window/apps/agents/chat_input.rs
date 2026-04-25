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

use super::state::*;

pub(crate) fn handle_click(rx: u32, ry: u32) -> bool {
    if ry < 30 && rx < 70 {
        set_view(VIEW_LIST);
        return true;
    }
    if ry >= 350 && rx < 400 {
        set_input_focused(true);
        return true;
    }
    if ry >= 350 && rx >= 400 {
        send_message();
        return true;
    }
    false
}

pub(crate) fn handle_key(ch: u8) {
    if !input_focused() {
        return;
    }
    let len = input_len();
    if ch == 8 && len > 0 {
        set_input_len(len - 1);
    } else if ch == 13 {
        send_message();
    } else if ch >= 32 && ch < 127 && len < 500 {
        unsafe {
            INPUT_BUF[len] = ch;
        }
        set_input_len(len + 1);
    }
}

fn send_message() {
    let len = input_len();
    if len == 0 {
        return;
    }
    let input = unsafe { &INPUT_BUF[..len] };
    crate::agents::executor::run_agent(selected(), input);
    set_input_len(0);
}
