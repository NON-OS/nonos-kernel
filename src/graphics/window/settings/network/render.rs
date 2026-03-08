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

use crate::bus::pci;
use crate::drivers::wifi as wifi_driver;
/* wireless class 0x0D for 802.11 adapters */
const CLASS_WIRELESS: u8 = 0x0D;
use crate::graphics::framebuffer::{fill_rect, COLOR_TEXT_WHITE};
use crate::graphics::window::settings::render::draw_string;

use super::ethernet;
use super::wifi;

/*
 * network panel was showing "no adapter detected" even when hardware exists
 * because it only checked if driver init succeeded. now we check pci devices
 * directly so users can see their hardware even if driver failed to load.
 */
pub(crate) fn draw(x: u32, y: u32, w: u32) {
    let mut cy = y;

    let wifi_hw_exists = has_wifi_hardware();

    if wifi_driver::is_available() {
        wifi::draw(x, cy, w);
        cy += 280;
    } else if wifi_hw_exists {
        draw_string(x + 15, cy, b"WiFi", COLOR_TEXT_WHITE);
        cy += 25;
        fill_rect(x + 15, cy, w - 30, 90, 0xFF1A1F26);
        draw_wifi_hardware_info(x + 25, cy + 8);
        draw_string(x + 25, cy + 30, b"Driver not loaded - firmware required", 0xFF5D6570);

        let loading = super::state::LOADING_FIRMWARE.load(core::sync::atomic::Ordering::Relaxed);
        let btn_color = if loading { 0xFF2D333B } else { 0xFF4A5568 };
        fill_rect(x + 25, cy + 52, 120, 30, btn_color);
        let btn_text: &[u8] = if loading { b"Loading..." } else { b"Load Firmware" };
        draw_string(x + 35, cy + 60, btn_text, COLOR_TEXT_WHITE);

        cy += 110;
    } else {
        draw_string(x + 15, cy, b"WiFi", COLOR_TEXT_WHITE);
        cy += 25;
        fill_rect(x + 15, cy, w - 30, 60, 0xFF1A1F26);
        draw_string(x + 25, cy + 10, b"No WiFi adapter detected", 0xFF7D8590);
        draw_string(x + 25, cy + 30, b"Connect WiFi hardware to scan networks", 0xFF5D6570);
        cy += 80;
    }

    fill_rect(x + 15, cy, w - 30, 1, 0xFF2D333B);
    cy += 15;

    ethernet::draw(x, cy, w);
}

fn has_wifi_hardware() -> bool {
    let count = pci::device_count();
    for i in 0..count {
        if let Some(dev) = pci::get_device(i) {
            if dev.class == CLASS_WIRELESS {
                return true;
            }
            if dev.class == 0x02 && dev.subclass == 0x80 {
                return true;
            }
        }
    }
    false
}

fn draw_wifi_hardware_info(x: u32, y: u32) {
    let count = pci::device_count();
    for i in 0..count {
        if let Some(dev) = pci::get_device(i) {
            if dev.class == CLASS_WIRELESS || (dev.class == 0x02 && dev.subclass == 0x80) {
                let name: &[u8] = match dev.vendor_id {
                    0x8086 => b"Intel WiFi",
                    0x10EC => b"Realtek WiFi",
                    0x14E4 => b"Broadcom WiFi",
                    0x168C => b"Atheros WiFi",
                    0x17CB => b"Qualcomm WiFi",
                    _ => b"WiFi Adapter",
                };
                draw_string(x, y, name, COLOR_TEXT_WHITE);

                let mut hex = [0u8; 20];
                hex[0..2].copy_from_slice(b"[");
                write_hex4(&mut hex[2..6], dev.vendor_id);
                hex[6] = b':';
                write_hex4(&mut hex[7..11], dev.device_id);
                hex[11] = b']';
                draw_string(x + 120, y, &hex[..12], 0xFF7D8590);
                return;
            }
        }
    }
}

fn write_hex4(buf: &mut [u8], val: u16) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    buf[0] = HEX[((val >> 12) & 0xF) as usize];
    buf[1] = HEX[((val >> 8) & 0xF) as usize];
    buf[2] = HEX[((val >> 4) & 0xF) as usize];
    buf[3] = HEX[(val & 0xF) as usize];
}
