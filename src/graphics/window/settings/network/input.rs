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
use crate::bus::pci;
use crate::drivers::wifi as wifi_driver;

use super::actions;
use super::click;
use super::state::*;

const CLASS_WIRELESS: u8 = 0x0D;

fn has_wifi_hardware() -> bool {
    let count = pci::device_count();
    for i in 0..count {
        if let Some(dev) = pci::get_device(i) {
            if dev.class == CLASS_WIRELESS || (dev.class == 0x02 && dev.subclass == 0x80) {
                return true;
            }
        }
    }
    false
}

pub(crate) fn handle_click(
    content_x: u32,
    content_y: u32,
    content_w: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    let wifi_available = wifi_driver::is_available();
    let wifi_hw = has_wifi_hardware();

    if wifi_available {
        if click::handle_wifi_click(content_x, content_y, content_w, click_x, click_y) {
            return true;
        }
        let eth_y = content_y + 280 + 15;
        return click::handle_ethernet_click(content_x, eth_y, content_w, click_x, click_y);
    }

    if wifi_hw {
        let btn_y = content_y + 25 + 52;
        if click_y >= btn_y as i32 && click_y < (btn_y + 30) as i32 {
            if click_x >= (content_x + 25) as i32 && click_x < (content_x + 145) as i32 {
                if !LOADING_FIRMWARE.load(Ordering::Relaxed) {
                    actions::do_load_firmware();
                }
                return true;
            }
        }
        let eth_y = content_y + 110 + 15;
        return click::handle_ethernet_click(content_x, eth_y, content_w, click_x, click_y);
    }

    let eth_y = content_y + 80 + 15;
    click::handle_ethernet_click(content_x, eth_y, content_w, click_x, click_y)
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
