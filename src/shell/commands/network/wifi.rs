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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED};
use crate::drivers::wifi;
use crate::shell::commands::utils::{trim_bytes, starts_with};

use super::scan::wifi_scan;
use super::connect::wifi_connect;

pub fn cmd_wifi(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        b"" as &[u8]
    };

    if args.is_empty() || args == b"status" {
        wifi_status();
    } else if args == b"scan" {
        wifi_scan();
    } else if starts_with(args, b"connect ") {
        wifi_connect(&args[8..]);
    } else if args == b"disconnect" {
        wifi_disconnect();
    } else if args == b"init" {
        wifi_init();
    } else {
        print_line(b"WiFi Commands:", COLOR_TEXT_WHITE);
        print_line(b"================================", COLOR_TEXT_DIM);
        print_line(b"  wifi              Show WiFi status", COLOR_TEXT);
        print_line(b"  wifi scan         Scan for networks", COLOR_TEXT);
        print_line(b"  wifi connect <ssid> <pass>", COLOR_TEXT);
        print_line(b"  wifi disconnect   Disconnect", COLOR_TEXT);
        print_line(b"  wifi init         Initialize driver", COLOR_TEXT);
    }
}

fn wifi_status() {
    print_line(b"WiFi Status:", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    if !wifi::is_available() {
        print_line(b"Status:     Not initialized", COLOR_YELLOW);
        print_line(b"", COLOR_TEXT);
        print_line(b"Run 'wifi init' to initialize driver", COLOR_TEXT_DIM);
        return;
    }

    if wifi::is_connected() {
        print_line(b"Status:     Connected", COLOR_GREEN);
        if let Some(info) = wifi::get_link_info() {
            let mut ssid_line = [0u8; 64];
            ssid_line[..12].copy_from_slice(b"SSID:       ");
            let ssid_bytes = info.ssid.as_bytes();
            let ssid_len = ssid_bytes.len().min(40);
            ssid_line[12..12+ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);
            print_line(&ssid_line[..12+ssid_len], COLOR_TEXT);

            let mut signal_line = [0u8; 32];
            signal_line[..12].copy_from_slice(b"Signal:     ");
            let rssi = info.rssi;
            if rssi < 0 {
                signal_line[12] = b'-';
                let val = (-rssi) as u8;
                if val >= 100 {
                    signal_line[13] = b'0' + (val / 100);
                    signal_line[14] = b'0' + ((val / 10) % 10);
                    signal_line[15] = b'0' + (val % 10);
                    signal_line[16..21].copy_from_slice(b" dBm");
                    print_line(&signal_line[..21], COLOR_TEXT);
                } else if val >= 10 {
                    signal_line[13] = b'0' + (val / 10);
                    signal_line[14] = b'0' + (val % 10);
                    signal_line[15..20].copy_from_slice(b" dBm");
                    print_line(&signal_line[..20], COLOR_TEXT);
                } else {
                    signal_line[13] = b'0' + val;
                    signal_line[14..19].copy_from_slice(b" dBm");
                    print_line(&signal_line[..19], COLOR_TEXT);
                }
            }

            let mut chan_line = [0u8; 32];
            chan_line[..12].copy_from_slice(b"Channel:    ");
            let ch = info.channel;
            if ch >= 100 {
                chan_line[12] = b'0' + (ch / 100);
                chan_line[13] = b'0' + ((ch / 10) % 10);
                chan_line[14] = b'0' + (ch % 10);
                print_line(&chan_line[..15], COLOR_TEXT);
            } else if ch >= 10 {
                chan_line[12] = b'0' + (ch / 10);
                chan_line[13] = b'0' + (ch % 10);
                print_line(&chan_line[..14], COLOR_TEXT);
            } else {
                chan_line[12] = b'0' + ch;
                print_line(&chan_line[..13], COLOR_TEXT);
            }
        }
    } else {
        print_line(b"Status:     Disconnected", COLOR_YELLOW);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Devices:    ", COLOR_TEXT_DIM);
    let count = wifi::device_count();
    if count == 0 {
        print_line(b"  No Intel WiFi detected", COLOR_TEXT_DIM);
    } else {
        print_line(b"  Intel WiFi adapter ready", COLOR_GREEN);
    }
}

fn wifi_init() {
    print_line(b"Initializing WiFi driver...", COLOR_TEXT);
    let count = wifi::init();
    if count > 0 {
        print_line(b"WiFi driver initialized", COLOR_GREEN);
        wifi::print_status();
    } else {
        print_line(b"No supported WiFi hardware found", COLOR_YELLOW);
        print_line(b"Supported: Intel AX200/AX201/AX210", COLOR_TEXT_DIM);
    }
}

fn wifi_disconnect() {
    if !wifi::is_available() {
        print_line(b"WiFi not initialized", COLOR_RED);
        return;
    }

    if !wifi::is_connected() {
        print_line(b"Not connected to any network", COLOR_YELLOW);
        return;
    }

    match wifi::disconnect() {
        Ok(()) => print_line(b"Disconnected", COLOR_GREEN),
        Err(_) => print_line(b"Disconnect failed", COLOR_RED),
    }
}
