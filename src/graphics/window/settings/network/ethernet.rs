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

use crate::bus::pci;
use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_GREEN, COLOR_TEXT_WHITE};
use crate::graphics::window::settings::render::draw_string;
use crate::network::stack::{is_link_up, is_network_available, is_network_connected};
use crate::network::{get_current_dns, get_current_gateway, get_current_ipv4, get_mac_address};
use crate::sys::settings::network as net_settings;

use super::helpers::{format_ip, format_ip_with_prefix, format_mac};
use super::state::{
    CONNECTING, CONNECTION_ERROR, STATIC_IP_BUFFER, STATIC_IP_EDITING, STATIC_IP_FIELD,
    STATIC_IP_LENS,
};

pub fn draw(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y, b"Ethernet", COLOR_TEXT_WHITE);

    let mut eth_count = 0u8;
    let mut eth_found = false;

    if crate::drivers::usb::rtl8152::is_connected() || crate::drivers::usb::cdc_eth::is_connected()
    {
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

    draw_connection_status(x, y, w);

    let mac = get_mac_address().unwrap_or([0; 6]);
    let mac_str = format_mac(&mac);
    draw_string(x + 25, y + 22, &mac_str, 0xFF7D8590);
}

fn draw_connection_status(x: u32, y: u32, w: u32) {
    let has_ip = is_network_connected();
    let link = is_link_up();
    let available = is_network_available();

    if has_ip && link {
        fill_rect(x + w - 100, y + 12, 16, 16, COLOR_GREEN);
        draw_string(x + w - 80, y + 14, b"READY", COLOR_GREEN);
    } else if link && available {
        fill_rect(x + w - 100, y + 12, 16, 16, 0xFFFFAA00);
        draw_string(x + w - 80, y + 14, b"NO IP", 0xFFFFAA00);
    } else if available {
        fill_rect(x + w - 100, y + 12, 16, 16, 0xFF7D8590);
        draw_string(x + w - 80, y + 14, b"DOWN", 0xFF7D8590);
    } else {
        fill_rect(x + w - 100, y + 12, 16, 16, 0xFF555555);
        draw_string(x + w - 80, y + 14, b"N/A", 0xFF555555);
    }
}

fn draw_interface_card(x: u32, y: u32, w: u32, idx: u8, _is_up: bool) {
    fill_rect(x + 15, y, w - 30, 40, 0xFF1A1F26);

    let mut name_buf = [0u8; 16];
    name_buf[0..3].copy_from_slice(b"eth");
    name_buf[3] = b'0' + idx;
    draw_string(x + 25, y + 6, &name_buf[..4], COLOR_TEXT_WHITE);

    let vendor_name = get_eth_vendor_name(idx);
    draw_string(x + 80, y + 6, vendor_name, 0xFF7D8590);

    draw_connection_status(x, y, w);

    let mac = get_mac_address().unwrap_or([0; 6]);
    let mac_str = format_mac(&mac);
    draw_string(x + 25, y + 22, &mac_str, 0xFF7D8590);
}

fn get_eth_vendor_name(idx: u8) -> &'static [u8] {
    let mut eth_idx = 0u8;
    let count = pci::device_count();
    for i in 0..count {
        if let Some(dev) = pci::get_device(i) {
            if dev.class == 0x02 && dev.subclass == 0x00 {
                if eth_idx == idx {
                    return match dev.vendor_id {
                        0x8086 => b"Intel",
                        0x10EC => b"Realtek",
                        0x14E4 => b"Broadcom",
                        0x1969 => b"Qualcomm",
                        0x10DE => b"NVIDIA",
                        0x1022 => b"AMD",
                        _ => b"PCI",
                    };
                }
                eth_idx += 1;
            }
        }
    }
    b"PCI"
}

fn draw_virtio_card(x: u32, y: u32, w: u32) {
    fill_rect(x + 15, y, w - 30, 40, 0xFF1A1F26);
    draw_string(x + 25, y + 6, b"virtio-net0", COLOR_TEXT_WHITE);
    draw_string(x + 130, y + 6, b"Virtual", 0xFF7D8590);

    draw_connection_status(x, y, w);

    let mac = get_mac_address().unwrap_or([0; 6]);
    let mac_str = format_mac(&mac);
    draw_string(x + 25, y + 22, &mac_str, 0xFF7D8590);
}

fn draw_ip_config(x: u32, y: u32, _w: u32) {
    draw_string(x + 15, y, b"IP Configuration", COLOR_TEXT_WHITE);

    let dhcp_enabled = net_settings::get_settings().dhcp_enabled;

    let dhcp_color = if dhcp_enabled { COLOR_ACCENT } else { 0xFF2D333B };
    fill_rect(x + 15, y + 22, 80, 28, dhcp_color);
    draw_string(x + 30, y + 28, b"DHCP", if dhcp_enabled { 0xFF0D1117 } else { COLOR_TEXT_WHITE });

    let static_color = if !dhcp_enabled { COLOR_ACCENT } else { 0xFF2D333B };
    fill_rect(x + 105, y + 22, 80, 28, static_color);
    draw_string(
        x + 120,
        y + 28,
        b"Static",
        if !dhcp_enabled { 0xFF0D1117 } else { COLOR_TEXT_WHITE },
    );

    let settings = net_settings::get_settings();
    let editing = STATIC_IP_EDITING.load(Ordering::Relaxed);
    let active_field = STATIC_IP_FIELD.load(Ordering::Relaxed);

    if dhcp_enabled {
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
    } else {
        let fields: [(&[u8], [u8; 4], u8); 4] = [
            (b"IP Address:", settings.static_ip, 0),
            (b"Subnet:", [settings.subnet_prefix, 0, 0, 0], 1),
            (b"Gateway:", settings.gateway, 2),
            (b"DNS:", settings.dns_primary, 3),
        ];

        for (i, (label, value, field_idx)) in fields.iter().enumerate() {
            let fy = y + 60 + (i as u32) * 22;
            draw_string(x + 15, fy, *label, 0xFF7D8590);

            let is_active = editing && active_field == *field_idx;
            let field_bg = if is_active { 0xFF2A3A4A } else { 0xFF1A1F26 };
            fill_rect(x + 100, fy - 2, 140, 18, field_bg);

            if is_active {
                let buf = STATIC_IP_BUFFER.lock();
                let lens = STATIC_IP_LENS.lock();
                let len = lens[*field_idx as usize] as usize;
                draw_string(x + 104, fy, &buf[*field_idx as usize][..len], COLOR_TEXT_WHITE);
                fill_rect(x + 104 + (len as u32) * 8, fy, 2, 14, COLOR_ACCENT);
            } else if *field_idx == 1 {
                let mut prefix_str = [b'/', b'0', b'0'];
                prefix_str[1] = b'0' + (value[0] / 10);
                prefix_str[2] = b'0' + (value[0] % 10);
                draw_string(x + 104, fy, &prefix_str, COLOR_TEXT_WHITE);
            } else {
                let ip_str = format_ip(value);
                draw_string(x + 104, fy, &ip_str, COLOR_TEXT_WHITE);
            }
        }
    }

    let connecting = CONNECTING.load(Ordering::Relaxed);
    let connect_color = if connecting { 0xFF2D333B } else { COLOR_GREEN };
    fill_rect(x + 200, y + 22, 90, 28, connect_color);
    let connect_text: &[u8] = if connecting { b"Wait..." } else { b"Connect" };
    draw_string(x + 215, y + 28, connect_text, 0xFF0D1117);

    fill_rect(x + 300, y + 22, 70, 28, COLOR_ACCENT);
    draw_string(x + 318, y + 28, b"Test", 0xFF0D1117);

    if let Some(err) = CONNECTION_ERROR.lock().as_ref() {
        let is_success = err.contains("reachable") || err.contains("Acquired");
        let bg_color = if is_success { 0xFF153415 } else { 0xFF4A1515 };
        let text_color = if is_success { 0xFF6BFF6B } else { 0xFFFF6B6B };
        fill_rect(x + 15, y + 120, 360, 24, bg_color);
        draw_string(x + 25, y + 125, err.as_bytes(), text_color);
    }
}
