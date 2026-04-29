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

use super::{bluetooth::BluetoothDevice, sound::AudioDevice, wifi::WifiNetwork};
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::{ACCENT, SUCCESS, TEXT_PRIMARY, TEXT_SECONDARY};

const ITEM_H: u32 = 36;
const MENU_W: u32 = 280;
const TOGGLE_W: u32 = 44;
const TOGGLE_H: u32 = 24;

pub(super) fn draw_toggle_item(x: u32, y: u32, label: &[u8], enabled: bool) {
    text::draw(x + 16, y + 10, label, TEXT_PRIMARY);
    let toggle_x = x + MENU_W - TOGGLE_W - 16;
    let toggle_bg = if enabled { SUCCESS } else { 0xFF444450 };
    primitives::rounded_rect(toggle_x, y + 6, TOGGLE_W, TOGGLE_H, 12, toggle_bg);
    let knob_x = if enabled { toggle_x + TOGGLE_W - 22 } else { toggle_x + 2 };
    primitives::rounded_rect(knob_x, y + 8, 20, 20, 10, 0xFFFFFFFF);
}

pub(super) fn draw_network_item(x: u32, y: u32, net: &WifiNetwork) {
    let color = if net.connected { ACCENT } else { TEXT_PRIMARY };
    text::draw(x + 16, y + 10, &net.ssid[..net.ssid_len], color);
    draw_signal_bars(x + MENU_W - 40, y + 10, net.signal);
    if net.secured {
        text::draw(x + MENU_W - 60, y + 10, b"@", TEXT_SECONDARY);
    }
}

fn draw_signal_bars(x: u32, y: u32, level: u8) {
    for i in 0..4u32 {
        let h = 4 + i * 3;
        let color = if (i as u8) < level { ACCENT } else { 0xFF444450 };
        primitives::rect(x + i * 6, y + (16 - h), 4, h, color);
    }
}

pub(super) fn draw_bt_device(x: u32, y: u32, dev: &BluetoothDevice) {
    let color = if dev.connected { ACCENT } else { TEXT_PRIMARY };
    text::draw(x + 16, y + 10, &dev.name[..dev.name_len], color);
    if dev.connected {
        text::draw(x + MENU_W - 80, y + 10, b"Connected", TEXT_SECONDARY);
    }
}

pub(super) fn draw_audio_device(x: u32, y: u32, dev: &AudioDevice) {
    text::draw(x + 16, y + 10, &dev.name[..dev.name_len], TEXT_PRIMARY);
}

pub(super) fn draw_volume_slider(x: u32, y: u32) {
    let vol = super::sound::get_volume();
    text::draw(x + 16, y + 10, b"Volume", TEXT_SECONDARY);
    draw_slider(x + 80, y + 12, vol);
}

pub(super) fn draw_brightness_slider(x: u32, y: u32) {
    let bright = super::control::get_brightness();
    text::draw(x + 16, y + 10, b"Display", TEXT_SECONDARY);
    draw_slider(x + 80, y + 12, bright);
}

fn draw_slider(x: u32, y: u32, value: u8) {
    let w = 160u32;
    primitives::rounded_rect(x, y, w, 8, 4, 0xFF444450);
    let fill_w = (value as u32 * w) / 100;
    if fill_w > 0 {
        primitives::rounded_rect(x, y, fill_w, 8, 4, ACCENT);
    }
    let knob_x = x + fill_w.saturating_sub(6);
    primitives::rounded_rect(knob_x, y - 2, 12, 12, 6, 0xFFFFFFFF);
}
