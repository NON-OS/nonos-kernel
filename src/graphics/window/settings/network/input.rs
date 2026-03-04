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

use core::sync::atomic::Ordering;
use crate::drivers::wifi as wifi_driver;

use super::actions;
use super::click;
use super::state::*;

pub(crate) fn handle_click(
    content_x: u32,
    content_y: u32,
    content_w: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    if wifi_driver::is_available() {
        return click::handle_wifi_click(content_x, content_y, content_w, click_x, click_y);
    }
    click::handle_ethernet_click(content_x, content_y, content_w, click_x, click_y)
}

pub(crate) fn handle_key(ch: u8) -> bool {
    if !SHOW_PASSWORD_DIALOG.load(Ordering::Relaxed) {
        return false;
    }

    let mut pwd_len = PASSWORD_LEN.load(Ordering::Relaxed);

    if ch == 0x08 || ch == 0x7F {
        if pwd_len > 0 {
            pwd_len -= 1;
            PASSWORD_LEN.store(pwd_len, Ordering::Relaxed);
        }
    } else if ch == 0x0D || ch == 0x0A {
        if !CONNECTING.load(Ordering::Relaxed) {
            actions::do_wifi_connect();
        }
    } else if ch == 0x1B {
        SHOW_PASSWORD_DIALOG.store(false, Ordering::Relaxed);
        SELECTED_NETWORK.store(255, Ordering::Relaxed);
    } else if ch >= 0x20 && ch < 0x7F && pwd_len < 63 {
        let mut pwd_buf = PASSWORD_BUFFER.lock();
        pwd_buf[pwd_len as usize] = ch;
        PASSWORD_LEN.store(pwd_len + 1, Ordering::Relaxed);
    }

    true
}
