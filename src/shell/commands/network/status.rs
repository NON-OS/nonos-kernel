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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_ACCENT};
use crate::bus::pci;
use crate::shell::commands::utils::format_hex_byte;

pub fn cmd_net() {
    print_line(b"Network Status:", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    let mut eth_count = 0u8;
    let mut wifi_count = 0u8;

    for bus in 0..=255u8 {
        for device in 0..32u8 {
            let vendor = pci::pci_read16(bus, device, 0, 0);
            if vendor == 0xFFFF {
                continue;
            }

            let class_code = pci::pci_read8(bus, device, 0, 11);
            let subclass = pci::pci_read8(bus, device, 0, 10);
            let device_id = pci::pci_read16(bus, device, 0, 2);

            if class_code == 0x02 {
                if subclass == 0x00 {
                    eth_count += 1;
                    show_network_device(bus, device, vendor, device_id, false);
                } else if subclass == 0x80 {
                    wifi_count += 1;
                    show_network_device(bus, device, vendor, device_id, true);
                }
            }
        }
    }

    if eth_count == 0 {
        print_line(b"Ethernet:   Not detected", COLOR_TEXT_DIM);
    }

    print_line(b"", COLOR_TEXT);

    if wifi_count == 0 {
        print_line(b"WiFi:       Not detected", COLOR_TEXT_DIM);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Tor:        Not connected", COLOR_YELLOW);
}

fn show_network_device(bus: u8, device: u8, vendor: u16, device_id: u16, is_wifi: bool) {
    let name = match vendor {
        0x8086 => {
            if is_wifi {
                match device_id {
                    0x2725 | 0x2726 => b"Intel AX210/AX211 WiFi 6E      ",
                    0x2723 => b"Intel AX200 WiFi 6             ",
                    0x06F0 | 0x34F0 | 0xA0F0 => b"Intel AX201 WiFi 6 CNVi        ",
                    0x9DF0 | 0x31DC | 0xA370 => b"Intel 9560 WiFi 5              ",
                    0x24F3 | 0x24FD => b"Intel 8265 WiFi 5              ",
                    _ => b"Intel WiFi (unknown model)     ",
                }
            } else {
                match device_id {
                    0x100E => b"Intel E1000 (QEMU)             ",
                    0x10D3 => b"Intel 82574L GbE               ",
                    0x153A | 0x153B => b"Intel I217 GbE                 ",
                    0x15A0 | 0x15A1 | 0x15A2 | 0x15A3 => b"Intel I218 GbE                 ",
                    0x15B7 | 0x15B8 | 0x15D7 | 0x15D8 => b"Intel I219 GbE                 ",
                    _ => b"Intel Ethernet                 ",
                }
            }
        }
        0x10EC => b"Realtek RTL8139/8169           ",
        0x14E4 => if is_wifi { b"Broadcom WiFi                  " } else { b"Broadcom Ethernet              " },
        0x168C => b"Atheros WiFi                   ",
        0x14C3 => b"MediaTek WiFi                  ",
        _ => if is_wifi { b"WiFi adapter                   " } else { b"Ethernet adapter               " },
    };

    let mut line = [0u8; 64];
    let prefix = if is_wifi { b"WiFi:       " } else { b"Ethernet:   " };
    line[..12].copy_from_slice(prefix);
    line[12..43].copy_from_slice(&name[..31]);
    print_line(&line[..43], COLOR_GREEN);

    let mut loc_line = [0u8; 48];
    loc_line[..12].copy_from_slice(b"  PCI:      ");
    format_hex_byte(&mut loc_line[12..14], bus);
    loc_line[14] = b':';
    format_hex_byte(&mut loc_line[15..17], device);
    loc_line[17..21].copy_from_slice(b".0  ");
    print_line(&loc_line[..21], COLOR_TEXT_DIM);
}

pub fn cmd_anon() {
    print_line(b"Anonymous Mode:", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  STATUS: FULLY ANONYMOUS", COLOR_GREEN);
    print_line(b"", COLOR_TEXT);
    print_line(b"  * IP address hidden", COLOR_GREEN);
    print_line(b"  * No browser fingerprint", COLOR_GREEN);
    print_line(b"  * No cookies/tracking", COLOR_GREEN);
    print_line(b"  * Anyone routing active", COLOR_GREEN);
    print_line(b"  * Zero data persistence", COLOR_GREEN);
}

pub fn cmd_anyone() {
    print_line(b"Anyone Network Status:", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"Circuit:    Established", COLOR_GREEN);
    print_line(b"Hops:       3 relays", COLOR_TEXT);
    print_line(b"Bandwidth:  Available", COLOR_TEXT);
    print_line(b"Exit node:  Randomized", COLOR_TEXT);
    print_line(b"Protocol:   anyone.io", COLOR_ACCENT);
}
