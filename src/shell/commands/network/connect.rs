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
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED};
use crate::drivers::wifi;
use crate::shell::commands::utils::trim_bytes;

pub(super) fn wifi_connect(args: &[u8]) {
    if !wifi::is_available() {
        print_line(b"WiFi not initialized. Run 'wifi init'", COLOR_RED);
        return;
    }

    let args = trim_bytes(args);
    if args.is_empty() {
        print_line(b"Usage: wifi connect <ssid> <password>", COLOR_TEXT_DIM);
        return;
    }

    let mut ssid_end = 0;
    let mut in_quote = false;
    for (i, &b) in args.iter().enumerate() {
        if b == b'"' {
            in_quote = !in_quote;
        } else if b == b' ' && !in_quote {
            ssid_end = i;
            break;
        }
    }

    if ssid_end == 0 {
        ssid_end = args.len();
    }

    let ssid_bytes = &args[..ssid_end];
    let ssid_clean = if ssid_bytes.starts_with(b"\"") && ssid_bytes.ends_with(b"\"") {
        &ssid_bytes[1..ssid_bytes.len()-1]
    } else {
        ssid_bytes
    };

    let password_bytes = if ssid_end < args.len() {
        trim_bytes(&args[ssid_end+1..])
    } else {
        b"" as &[u8]
    };

    let password_clean = if password_bytes.starts_with(b"\"") && password_bytes.ends_with(b"\"") {
        &password_bytes[1..password_bytes.len()-1]
    } else {
        password_bytes
    };

    let ssid = core::str::from_utf8(ssid_clean).unwrap_or("");
    let password = core::str::from_utf8(password_clean).unwrap_or("");

    let mut line = [0u8; 64];
    line[..15].copy_from_slice(b"Connecting to: ");
    let ssid_len = ssid.len().min(40);
    line[15..15+ssid_len].copy_from_slice(&ssid.as_bytes()[..ssid_len]);
    print_line(&line[..15+ssid_len], COLOR_TEXT);

    match wifi::connect(ssid, password) {
        Ok(()) => {
            print_line(b"Connected successfully!", COLOR_GREEN);
            if let Some(info) = wifi::get_link_info() {
                let mut signal_line = [0u8; 32];
                signal_line[..8].copy_from_slice(b"Signal: ");
                let val = (-info.rssi) as u8;
                signal_line[8] = b'-';
                signal_line[9] = b'0' + (val / 10);
                signal_line[10] = b'0' + (val % 10);
                signal_line[11..16].copy_from_slice(b" dBm");
                print_line(&signal_line[..16], COLOR_TEXT_DIM);
            }
        }
        Err(e) => {
            print_line(b"Connection failed:", COLOR_RED);
            let msg = e.as_str().as_bytes();
            let msg_len = msg.len().min(60);
            let mut err_line = [0u8; 64];
            err_line[..msg_len].copy_from_slice(&msg[..msg_len]);
            print_line(&err_line[..msg_len], COLOR_RED);
        }
    }
}
