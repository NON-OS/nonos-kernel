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

use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};
use crate::graphics::window::settings::render::draw_string;
use crate::bus::pci;
use crate::sys::settings::network as net_settings;
use crate::network::{get_current_ipv4, get_current_gateway, get_current_dns, get_mac_address};
use crate::network::stack::{is_network_available, is_network_connected};

use super::helpers::{format_mac, format_ip, format_ip_with_prefix};

pub fn draw(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y, b"Ethernet", COLOR_TEXT_WHITE);

    let mut eth_count = 0u8;
    let mut eth_found = false;

    if crate::drivers::usb::rtl8152::is_connected() || crate::drivers::usb::cdc_eth::is_connected() {
        let iy = y + 25 + (eth_count as u32) * 45;
        draw_usb_eth_card(x, iy, w);
        eth_found = true;
        eth_count += 1;
    }

    let pci_count = pci::device_count();
    for i in 0..pci_count {
        if let Some(dev) = pci::get_device(i) {
            if dev.class == 0x02 && dev.subclass == 0x00 {
                let iy = y + 25 + (eth_count as u32) * 45;
                draw_interface_card(x, iy, w, eth_count, true);
                eth_found = true;
                eth_count += 1;
                if eth_count >= 4 {
                    break;
                }
            }
        }
    }

    if !eth_found {
        let iy = y + 25;
        if is_network_available() {
            draw_virtio_card(x, iy, w);
        } else {
            fill_rect(x + 15, iy, w - 30, 40, 0xFF1A1F26);
            draw_string(x + 25, iy + 12, b"No Ethernet adapter detected", 0xFF7D8590);
        }
        eth_count = 1;
    }

    let ip_y = y + 30 + (eth_count as u32) * 45 + 20;
    draw_ip_config(x, ip_y, w);
}

fn draw_usb_eth_card(x: u32, y: u32, w: u32) {
    fill_rect(x + 15, y, w - 30, 40, 0xFF1A1F26);
    draw_string(x + 25, y + 6, b"usb-eth0", COLOR_TEXT_WHITE);
    draw_string(x + 110, y + 6, b"USB CDC", 0xFF7D8590);

    let connected = is_network_connected();
    let available = is_network_available();

    if connected {
        fill_rect(x + w - 100, y + 12, 16, 16, COLOR_GREEN);
        draw_string(x + w - 80, y + 14, b"ONLINE", COLOR_GREEN);
    } else if available {
        fill_rect(x + w - 100, y + 12, 16, 16, 0xFFFFAA00);
        draw_string(x + w - 80, y + 14, b"NO IP", 0xFFFFAA00);
    } else {
        fill_rect(x + w - 100, y + 12, 16, 16, 0xFF7D8590);
        draw_string(x + w - 80, y + 14, b"DOWN", 0xFF7D8590);
    }

    let mac = get_mac_address();
    let mac_str = format_mac(&mac);
    draw_string(x + 25, y + 22, &mac_str, 0xFF7D8590);
}

fn draw_interface_card(x: u32, y: u32, w: u32, idx: u8, _is_up: bool) {
    fill_rect(x + 15, y, w - 30, 40, 0xFF1A1F26);

    let mut name_buf = [0u8; 16];
    name_buf[0..3].copy_from_slice(b"eth");
    name_buf[3] = b'0' + idx;
    draw_string(x + 25, y + 6, &name_buf[..4], COLOR_TEXT_WHITE);
    draw_string(x + 80, y + 6, b"PCI", 0xFF7D8590);

    let connected = is_network_connected();
    let available = is_network_available();

    if connected {
        fill_rect(x + w - 100, y + 12, 16, 16, COLOR_GREEN);
        draw_string(x + w - 80, y + 14, b"ONLINE", COLOR_GREEN);
    } else if available {
        fill_rect(x + w - 100, y + 12, 16, 16, 0xFFFFAA00);
        draw_string(x + w - 80, y + 14, b"NO IP", 0xFFFFAA00);
    } else {
        fill_rect(x + w - 100, y + 12, 16, 16, 0xFF7D8590);
        draw_string(x + w - 80, y + 14, b"DOWN", 0xFF7D8590);
    }

    let mac = get_mac_address();
    let mac_str = format_mac(&mac);
    draw_string(x + 25, y + 22, &mac_str, 0xFF7D8590);
}

fn draw_virtio_card(x: u32, y: u32, w: u32) {
    fill_rect(x + 15, y, w - 30, 40, 0xFF1A1F26);
    draw_string(x + 25, y + 6, b"virtio-net0", COLOR_TEXT_WHITE);
    draw_string(x + 130, y + 6, b"Virtual", 0xFF7D8590);

    let connected = is_network_connected();
    let available = is_network_available();

    if connected {
        fill_rect(x + w - 100, y + 12, 16, 16, COLOR_GREEN);
        draw_string(x + w - 80, y + 14, b"ONLINE", COLOR_GREEN);
    } else if available {
        fill_rect(x + w - 100, y + 12, 16, 16, 0xFFFFAA00);
        draw_string(x + w - 80, y + 14, b"NO IP", 0xFFFFAA00);
    } else {
        fill_rect(x + w - 100, y + 12, 16, 16, 0xFF7D8590);
        draw_string(x + w - 80, y + 14, b"DOWN", 0xFF7D8590);
    }

    let mac = get_mac_address();
    let mac_str = format_mac(&mac);
    draw_string(x + 25, y + 22, &mac_str, 0xFF7D8590);
}

fn draw_ip_config(x: u32, y: u32, _w: u32) {
    draw_string(x + 15, y, b"IP Configuration", COLOR_TEXT_WHITE);

    let dhcp_enabled = net_settings::get_settings().dhcp_enabled;

    let dhcp_color = if dhcp_enabled { COLOR_ACCENT } else { 0xFF2D333B };
    fill_rect(x + 15, y + 22, 80, 28, dhcp_color);
    draw_string(
        x + 30,
        y + 28,
        b"DHCP",
        if dhcp_enabled {
            0xFF0D1117
        } else {
            COLOR_TEXT_WHITE
        },
    );

    let static_color = if !dhcp_enabled {
        COLOR_ACCENT
    } else {
        0xFF2D333B
    };
    fill_rect(x + 105, y + 22, 80, 28, static_color);
    draw_string(
        x + 120,
        y + 28,
        b"Static",
        if !dhcp_enabled {
            0xFF0D1117
        } else {
            COLOR_TEXT_WHITE
        },
    );

    draw_string(x + 15, y + 60, b"Current IP:", 0xFF7D8590);
    if let Some((ip, prefix)) = get_current_ipv4() {
        let ip_str = format_ip_with_prefix(&ip, prefix);
        draw_string(x + 100, y + 60, &ip_str, COLOR_TEXT_WHITE);
    } else {
        draw_string(x + 100, y + 60, b"Not configured", 0xFF7D8590);
    }

    draw_string(x + 15, y + 78, b"Gateway:", 0xFF7D8590);
    if let Some(gw) = get_current_gateway() {
        let gw_str = format_ip(&gw);
        draw_string(x + 100, y + 78, &gw_str, COLOR_TEXT_WHITE);
    } else {
        draw_string(x + 100, y + 78, b"Not set", 0xFF7D8590);
    }

    draw_string(x + 15, y + 96, b"DNS:", 0xFF7D8590);
    let dns = get_current_dns();
    let dns_str = format_ip(&dns);
    draw_string(x + 100, y + 96, &dns_str, COLOR_TEXT_WHITE);
}
