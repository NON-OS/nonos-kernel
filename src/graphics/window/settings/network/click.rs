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
use crate::drivers::wifi;
use crate::drivers::wifi::scan::SecurityType;
use crate::sys::settings::network as net_settings;
use crate::graphics::window::settings::state::*;

use super::state::*;
use super::actions::*;

pub fn handle_wifi_click(x: u32, y: u32, w: u32, click_x: i32, click_y: i32) -> bool {
    if SHOW_PASSWORD_DIALOG.load(Ordering::Relaxed) {
        return handle_password_dialog_click(x, y, w, click_x, click_y);
    }

    let connected = wifi::is_connected();
    let base_y = if connected { y + 25 + 65 + 5 } else { y + 25 + 5 };

    if click_y >= base_y as i32 && click_y < (base_y + 32) as i32 {
        if click_x >= (x + 15) as i32 && click_x < (x + 125) as i32 {
            if !WIFI_SCANNING.load(Ordering::Relaxed)
                && !CONNECTING.load(Ordering::Relaxed)
                && !LOADING_FIRMWARE.load(Ordering::Relaxed)
            {
                do_wifi_scan();
            }
            return true;
        }

        if connected && click_x >= (x + 135) as i32 && click_x < (x + 230) as i32 {
            do_wifi_disconnect();
            return true;
        }

        let fw_btn_x = if connected { x + 240 } else { x + 135 };
        if click_x >= fw_btn_x as i32 && click_x < (fw_btn_x + 105) as i32 {
            if !LOADING_FIRMWARE.load(Ordering::Relaxed) {
                do_load_firmware();
            }
            return true;
        }
    }

    let list_y = base_y + 45 + 25;
    let results = CACHED_SCAN_RESULTS.lock();
    for i in 0..results.len().min(6) {
        let item_y = list_y + (i as u32) * 38;
        if click_y >= item_y as i32 && click_y < (item_y + 34) as i32 {
            if click_x >= (x + 15) as i32 && click_x < (x + w - 15) as i32 {
                SELECTED_NETWORK.store(i as u8, Ordering::Relaxed);

                if results[i].security != SecurityType::Open {
                    PASSWORD_LEN.store(0, Ordering::Relaxed);
                    *CONNECTION_ERROR.lock() = None;
                    SHOW_PASSWORD_DIALOG.store(true, Ordering::Relaxed);
                } else {
                    drop(results);
                    do_wifi_connect_open();
                }
                return true;
            }
        }
    }

    false
}

fn handle_password_dialog_click(
    base_x: u32,
    base_y: u32,
    base_w: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    let dialog_w = 320u32;
    let dialog_h = 160u32;
    let dialog_x = base_x + (base_w - dialog_w) / 2;
    let dialog_y = base_y + 80;

    if click_y < dialog_y as i32 || click_y > (dialog_y + dialog_h) as i32 {
        return false;
    }

    if click_y >= (dialog_y + 100) as i32 && click_y < (dialog_y + 132) as i32 {
        if click_x >= (dialog_x + 15) as i32 && click_x < (dialog_x + 105) as i32 {
            SHOW_PASSWORD_DIALOG.store(false, Ordering::Relaxed);
            SELECTED_NETWORK.store(255, Ordering::Relaxed);
            return true;
        }

        if click_x >= (dialog_x + dialog_w - 105) as i32
            && click_x < (dialog_x + dialog_w - 15) as i32
        {
            if !CONNECTING.load(Ordering::Relaxed) {
                do_wifi_connect();
            }
            return true;
        }
    }

    true
}

pub fn handle_ethernet_click(
    content_x: u32,
    content_y: u32,
    _content_w: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    let ip_y = content_y + 45 + 30 + 45 + 20;
    let dhcp_btn_y = ip_y + 22;

    if click_y >= dhcp_btn_y as i32 && click_y < (dhcp_btn_y + 28) as i32 {
        if click_x >= (content_x + 15) as i32 && click_x < (content_x + 95) as i32 {
            set_dhcp_enabled(true);
            let mut settings = net_settings::get_settings();
            settings.dhcp_enabled = true;
            net_settings::update_settings(settings);
            return true;
        }
        if click_x >= (content_x + 105) as i32 && click_x < (content_x + 185) as i32 {
            set_dhcp_enabled(false);
            let mut settings = net_settings::get_settings();
            settings.dhcp_enabled = false;
            net_settings::update_settings(settings);
            return true;
        }
    }

    false
}
