// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::items::{
    draw_audio_device, draw_brightness_slider, draw_bt_device, draw_network_item, draw_toggle_item,
    draw_volume_slider,
};
use super::state::{get_active, TrayMenu};
use super::{bluetooth, control, sound, wifi};
use crate::graphics::components::primitives;

const MENU_W: u32 = 280;
const ITEM_H: u32 = 36;
const BG: u32 = 0xF0202028;
const HOVER_BG: u32 = 0xFF2A3A4A;

pub fn draw(sw: u32) {
    let menu = get_active();
    if menu == TrayMenu::None {
        return;
    }
    let (x, y, w, h) = menu_bounds(menu, sw);
    primitives::rounded_rect(x as u32, y as u32, w, h, 12, BG);
    match menu {
        TrayMenu::Wifi => draw_wifi(x as u32, y as u32),
        TrayMenu::Bluetooth => draw_bluetooth(x as u32, y as u32),
        TrayMenu::Sound => draw_sound(x as u32, y as u32),
        TrayMenu::Control => draw_control(x as u32, y as u32),
        TrayMenu::None => {}
    }
}

pub(super) fn menu_bounds(menu: TrayMenu, sw: u32) -> (i32, i32, u32, u32) {
    let x = (sw - MENU_W - 16) as i32;
    let y = 38i32;
    let h = match menu {
        TrayMenu::Wifi => 5 * ITEM_H + 16,
        TrayMenu::Bluetooth => 4 * ITEM_H + 16,
        TrayMenu::Sound => 4 * ITEM_H + 16,
        TrayMenu::Control => 6 * ITEM_H + 16,
        TrayMenu::None => 0,
    };
    (x, y, MENU_W, h)
}

fn draw_wifi(x: u32, y: u32) {
    let enabled = wifi::is_enabled();
    draw_toggle_item(x, y + 8, b"Wi-Fi", enabled);
    if enabled {
        let mut idx = 1u32;
        for net in wifi::get_wifi_networks().take(4) {
            draw_network_item(x, y + 8 + idx * ITEM_H, net);
            idx += 1;
        }
    }
}

fn draw_bluetooth(x: u32, y: u32) {
    let enabled = bluetooth::is_enabled();
    draw_toggle_item(x, y + 8, b"Bluetooth", enabled);
    if enabled {
        let mut idx = 1u32;
        for dev in bluetooth::get_bluetooth_devices().take(3) {
            draw_bt_device(x, y + 8 + idx * ITEM_H, dev);
            idx += 1;
        }
    }
}

fn draw_sound(x: u32, y: u32) {
    let muted = sound::is_muted();
    draw_toggle_item(x, y + 8, b"Sound", !muted);
    draw_volume_slider(x, y + 8 + ITEM_H);
    let mut idx = 2u32;
    for dev in sound::get_output_devices().take(2) {
        draw_audio_device(x, y + 8 + idx * ITEM_H, dev);
        idx += 1;
    }
}

fn draw_control(x: u32, y: u32) {
    draw_toggle_item(x, y + 8, b"Wi-Fi", wifi::is_enabled());
    draw_toggle_item(x, y + 8 + ITEM_H, b"Bluetooth", bluetooth::is_enabled());
    draw_toggle_item(x, y + 8 + 2 * ITEM_H, b"Airplane Mode", control::get_airplane_mode());
    draw_toggle_item(x, y + 8 + 3 * ITEM_H, b"Do Not Disturb", control::get_do_not_disturb());
    draw_toggle_item(x, y + 8 + 4 * ITEM_H, b"Night Shift", control::get_night_shift());
    draw_brightness_slider(x, y + 8 + 5 * ITEM_H);
}
