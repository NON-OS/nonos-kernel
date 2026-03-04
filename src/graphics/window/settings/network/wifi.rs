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
use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};
use crate::graphics::window::settings::render::draw_string;
use crate::drivers::wifi;
use crate::drivers::wifi::{ScanResult, scan::SecurityType};

use super::state::*;
use super::helpers::*;
use super::dialogs::draw_password_dialog;

pub fn draw(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y, b"WiFi", COLOR_TEXT_WHITE);

    let connected = wifi::is_connected();
    let status_color = if connected { COLOR_GREEN } else { 0xFFFFB800 };
    let status_text: &[u8] = if connected {
        b"Connected"
    } else {
        b"Not Connected"
    };
    fill_rect(x + w - 120, y - 2, 105, 20, 0xFF1A1F26);
    draw_string(x + w - 115, y, status_text, status_color);

    let mut cy = y + 25;

    if connected {
        if let Some(info) = wifi::get_link_info() {
            fill_rect(x + 15, cy, w - 30, 55, 0xFF1A2633);

            draw_string(x + 25, cy + 8, info.ssid.as_bytes(), COLOR_TEXT_WHITE);

            let bars = signal_to_bars(info.rssi);
            for i in 0..4u32 {
                let bar_h = 6 + i * 4;
                let bar_color = if i < bars { COLOR_GREEN } else { 0xFF2D333B };
                fill_rect(x + w - 75 + i * 12, cy + 35 - bar_h, 8, bar_h, bar_color);
            }

            draw_string(x + 25, cy + 28, b"Ch:", 0xFF7D8590);
            draw_string(
                x + 50,
                cy + 28,
                &num_to_bytes(info.channel as u32),
                COLOR_TEXT_WHITE,
            );

            draw_string(x + 90, cy + 28, b"Signal:", 0xFF7D8590);
            let rssi_str = rssi_to_str(info.rssi);
            draw_string(x + 145, cy + 28, &rssi_str, signal_color(info.rssi));

            draw_string(x + 25, cy + 42, b"Speed:", 0xFF7D8590);
            draw_string(x + 75, cy + 42, &speed_to_str(info.tx_rate), COLOR_TEXT_WHITE);

            cy += 65;
        }
    }

    cy += 5;
    let scanning = WIFI_SCANNING.load(Ordering::Relaxed);
    let connecting = CONNECTING.load(Ordering::Relaxed);
    let loading_fw = LOADING_FIRMWARE.load(Ordering::Relaxed);

    let scan_color = if scanning || connecting || loading_fw {
        0xFF2D333B
    } else {
        COLOR_ACCENT
    };
    fill_rect(x + 15, cy, 110, 32, scan_color);
    let scan_text: &[u8] = if scanning {
        b"Scanning..."
    } else {
        b"Scan Networks"
    };
    draw_string(
        x + 22,
        cy + 9,
        scan_text,
        if scanning || loading_fw { 0xFF7D8590 } else { 0xFF0D1117 },
    );

    let fw_btn_x = if connected { x + 240 } else { x + 135 };
    let fw_color = if loading_fw { 0xFF2D333B } else { 0xFF4A5568 };
    fill_rect(fw_btn_x, cy, 105, 32, fw_color);
    let fw_text: &[u8] = if loading_fw { b"Loading..." } else { b"Load Firmware" };
    draw_string(fw_btn_x + 8, cy + 9, fw_text, COLOR_TEXT_WHITE);

    if connected {
        fill_rect(x + 135, cy, 95, 32, 0xFF8B0000);
        draw_string(x + 148, cy + 9, b"Disconnect", COLOR_TEXT_WHITE);
    }

    cy += 45;

    if let Some(err) = CONNECTION_ERROR.lock().as_ref() {
        fill_rect(x + 15, cy, w - 30, 24, 0xFF4A1515);
        draw_string(x + 25, cy + 5, err.as_bytes(), 0xFFFF6B6B);
        cy += 30;
    }

    draw_string(x + 15, cy, b"Available Networks", COLOR_TEXT_WHITE);
    cy += 25;

    let results = CACHED_SCAN_RESULTS.lock();
    let selected = SELECTED_NETWORK.load(Ordering::Relaxed);

    if results.is_empty() && !scanning {
        draw_string(
            x + 25,
            cy + 10,
            b"Click 'Scan Networks' to find WiFi",
            0xFF7D8590,
        );
    } else {
        for (i, network) in results.iter().enumerate().take(6) {
            let is_selected = selected == i as u8;
            draw_network_entry(x, cy, w, network, is_selected);
            cy += 38;
        }
    }
    drop(results);

    if SHOW_PASSWORD_DIALOG.load(Ordering::Relaxed) {
        draw_password_dialog(x, y, w);
    }
}

fn draw_network_entry(x: u32, y: u32, w: u32, network: &ScanResult, selected: bool) {
    let bg_color = if selected { 0xFF2D4A6B } else { 0xFF1A1F26 };
    fill_rect(x + 15, y, w - 30, 34, bg_color);

    let security_icon: &[u8] = match network.security {
        SecurityType::Open => b"[ ]",
        SecurityType::Wep => b"[!]",
        SecurityType::WpaPsk | SecurityType::Wpa2Psk | SecurityType::Wpa3Sae => b"[*]",
        SecurityType::Enterprise => b"[E]",
        SecurityType::Unknown => b"[?]",
    };
    let sec_color = match network.security {
        SecurityType::Open => 0xFF7D8590,
        SecurityType::Wep => 0xFFFF6B6B,
        SecurityType::WpaPsk | SecurityType::Wpa2Psk | SecurityType::Wpa3Sae => 0xFFFFB800,
        SecurityType::Enterprise => 0xFF00D4FF,
        SecurityType::Unknown => 0xFF7D8590,
    };
    draw_string(x + 22, y + 10, security_icon, sec_color);

    let ssid_bytes = network.ssid.as_bytes();
    draw_string(x + 52, y + 10, ssid_bytes, COLOR_TEXT_WHITE);

    let bars = signal_to_bars(network.rssi);
    for i in 0..4u32 {
        let bar_h = 5 + i * 4;
        let bar_color = if i < bars { COLOR_GREEN } else { 0xFF2D333B };
        fill_rect(x + w - 65 + i * 11, y + 22 - bar_h, 7, bar_h, bar_color);
    }

    let sec_text: &[u8] = match network.security {
        SecurityType::Open => b"Open",
        SecurityType::Wep => b"WEP",
        SecurityType::WpaPsk => b"WPA",
        SecurityType::Wpa2Psk => b"WPA2",
        SecurityType::Wpa3Sae => b"WPA3",
        SecurityType::Enterprise => b"EAP",
        SecurityType::Unknown => b"?",
    };
    draw_string(x + w - 110, y + 10, sec_text, 0xFF7D8590);
}
