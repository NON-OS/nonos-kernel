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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_ACCENT};
use crate::drivers::wifi;

pub(super) fn wifi_scan() {
    if !wifi::is_available() {
        print_line(b"WiFi not initialized. Run 'wifi init'", COLOR_RED);
        return;
    }

    print_line(b"Scanning for networks...", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);

    match wifi::scan() {
        Ok(results) => {
            if results.is_empty() {
                print_line(b"No networks found", COLOR_YELLOW);
            } else {
                print_line(b"SSID                          Signal  Ch  Security", COLOR_TEXT_WHITE);
                print_line(b"====================================================", COLOR_TEXT_DIM);

                for network in results.iter().take(15) {
                    let mut line = [0u8; 64];
                    let ssid_bytes = network.ssid.as_bytes();
                    let ssid_len = ssid_bytes.len().min(28);
                    line[..ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);
                    for i in ssid_len..30 {
                        line[i] = b' ';
                    }

                    let rssi = network.rssi;
                    if rssi < 0 {
                        line[30] = b'-';
                        let val = (-rssi) as u8;
                        line[31] = b'0' + (val / 10);
                        line[32] = b'0' + (val % 10);
                    } else {
                        line[30..33].copy_from_slice(b"  0");
                    }
                    line[33..38].copy_from_slice(b"dBm  ");

                    let ch = network.channel;
                    if ch >= 100 {
                        line[38] = b'0' + (ch / 100);
                        line[39] = b'0' + ((ch / 10) % 10);
                        line[40] = b'0' + (ch % 10);
                    } else if ch >= 10 {
                        line[38] = b' ';
                        line[39] = b'0' + (ch / 10);
                        line[40] = b'0' + (ch % 10);
                    } else {
                        line[38] = b' ';
                        line[39] = b' ';
                        line[40] = b'0' + ch;
                    }
                    line[41..44].copy_from_slice(b"   ");

                    let sec = match network.security {
                        wifi::scan::SecurityType::Open => b"Open",
                        wifi::scan::SecurityType::Wep => b"WEP ",
                        wifi::scan::SecurityType::WpaPsk => b"WPA ",
                        wifi::scan::SecurityType::Wpa2Psk => b"WPA2",
                        wifi::scan::SecurityType::Wpa3Sae => b"WPA3",
                        _ => b"????",
                    };
                    line[44..48].copy_from_slice(sec);

                    let color = if network.rssi > -50 { COLOR_GREEN }
                                else if network.rssi > -70 { COLOR_ACCENT }
                                else { COLOR_TEXT };
                    print_line(&line[..48], color);
                }

                print_line(b"", COLOR_TEXT);
                let mut count_line = [0u8; 32];
                count_line[..7].copy_from_slice(b"Found: ");
                let count = results.len();
                if count >= 10 {
                    count_line[7] = b'0' + (count / 10) as u8;
                    count_line[8] = b'0' + (count % 10) as u8;
                    count_line[9..18].copy_from_slice(b" networks");
                    print_line(&count_line[..18], COLOR_TEXT_DIM);
                } else {
                    count_line[7] = b'0' + count as u8;
                    count_line[8..17].copy_from_slice(b" networks");
                    print_line(&count_line[..17], COLOR_TEXT_DIM);
                }
            }
        }
        Err(e) => {
            print_line(b"Scan failed:", COLOR_RED);
            let msg = e.as_str().as_bytes();
            let msg_len = msg.len().min(60);
            let mut err_line = [0u8; 64];
            err_line[..msg_len].copy_from_slice(&msg[..msg_len]);
            print_line(&err_line[..msg_len], COLOR_RED);
        }
    }
}
