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
use crate::drivers::wifi as wifi_driver;

use super::actions;
use super::click;
use super::state::{
    WIFI_SCANNING, SELECTED_NETWORK, SHOW_PASSWORD_DIALOG, PASSWORD_BUFFER, PASSWORD_LEN,
    CONNECTING, LOADING_FIRMWARE, STATIC_IP_EDITING, STATIC_IP_FIELD, STATIC_IP_BUFFER, STATIC_IP_LENS
};

const CLASS_WIRELESS: u8 = 0x0D;

fn has_wifi_hardware() -> bool {
    let count = pci::device_count();
    for i in 0..count {
        if let Some(dev) = pci::get_device(i) {
            if dev.class == CLASS_WIRELESS || (dev.class == 0x02 && dev.subclass == 0x80) {
                return true;
            }
        }
    }
    false
}

pub(crate) fn handle_click(
    content_x: u32,
    content_y: u32,
    content_w: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    let wifi_available = wifi_driver::is_available();
    let wifi_hw = has_wifi_hardware();

    if wifi_available {
        if click::handle_wifi_click(content_x, content_y, content_w, click_x, click_y) {
            return true;
        }
        let eth_y = content_y + 280 + 15;
        if click::handle_static_ip_click(content_x, eth_y, click_x, click_y) {
            return true;
        }
        return click::handle_ethernet_click(content_x, eth_y, content_w, click_x, click_y);
    }

    if wifi_hw {
        let btn_y = content_y + 25 + 52;
        if click_y >= btn_y as i32 && click_y < (btn_y + 30) as i32 {
            if click_x >= (content_x + 25) as i32 && click_x < (content_x + 145) as i32 {
                if !LOADING_FIRMWARE.load(Ordering::Relaxed) {
                    actions::do_load_firmware();
                }
                return true;
            }
        }
        let eth_y = content_y + 110 + 15;
        if click::handle_static_ip_click(content_x, eth_y, click_x, click_y) {
            return true;
        }
        return click::handle_ethernet_click(content_x, eth_y, content_w, click_x, click_y);
    }

    let eth_y = content_y + 80 + 15;
    if click::handle_static_ip_click(content_x, eth_y, click_x, click_y) {
        return true;
    }
    click::handle_ethernet_click(content_x, eth_y, content_w, click_x, click_y)
}

pub(crate) fn handle_key(ch: u8) -> bool {
    if STATIC_IP_EDITING.load(Ordering::Relaxed) {
        return handle_static_ip_key(ch);
    }

    if !SHOW_PASSWORD_DIALOG.load(Ordering::Relaxed) {
        return false;
    }

    let mut pwd_len = PASSWORD_LEN.load(Ordering::Relaxed);

    if ch == 0x08 || ch == 0x7F {
        if pwd_len > 0 {
            pwd_len -= 1;
            PASSWORD_LEN.store(pwd_len, Ordering::Relaxed);
        }
    } else if ch == 0x0D || ch == 0x0A {
        if !CONNECTING.load(Ordering::Relaxed) {
            actions::do_wifi_connect();
        }
    } else if ch == 0x1B {
        SHOW_PASSWORD_DIALOG.store(false, Ordering::Relaxed);
        SELECTED_NETWORK.store(255, Ordering::Relaxed);
    } else if ch >= 0x20 && ch < 0x7F && pwd_len < 63 {
        let mut pwd_buf = PASSWORD_BUFFER.lock();
        pwd_buf[pwd_len as usize] = ch;
        PASSWORD_LEN.store(pwd_len + 1, Ordering::Relaxed);
    }

    true
}

fn handle_static_ip_key(ch: u8) -> bool {
    use crate::sys::settings::network as net_settings;

    let field = STATIC_IP_FIELD.load(Ordering::Relaxed) as usize;
    let mut buf = STATIC_IP_BUFFER.lock();
    let mut lens = STATIC_IP_LENS.lock();
    let len = lens[field] as usize;

    if ch == 0x08 || ch == 0x7F {
        if len > 0 {
            lens[field] = (len - 1) as u8;
        }
    } else if ch == 0x0D || ch == 0x0A {
        if let Some(parsed) = parse_ip_field(&buf[field][..len], field as u8) {
            let mut settings = net_settings::get_settings();
            match field {
                0 => settings.static_ip = parsed,
                1 => settings.subnet_prefix = parsed[0],
                2 => settings.gateway = parsed,
                3 => settings.dns_primary = parsed,
                _ => {}
            }
            net_settings::update_settings(settings);
        }
        STATIC_IP_EDITING.store(false, Ordering::Relaxed);
    } else if ch == 0x1B {
        STATIC_IP_EDITING.store(false, Ordering::Relaxed);
    } else if ch == 0x09 {
        if let Some(parsed) = parse_ip_field(&buf[field][..len], field as u8) {
            let mut settings = net_settings::get_settings();
            match field {
                0 => settings.static_ip = parsed,
                1 => settings.subnet_prefix = parsed[0],
                2 => settings.gateway = parsed,
                3 => settings.dns_primary = parsed,
                _ => {}
            }
            net_settings::update_settings(settings);
        }
        let next = (field + 1) % 4;
        STATIC_IP_FIELD.store(next as u8, Ordering::Relaxed);

        let settings = net_settings::get_settings();
        let value = match next {
            0 => settings.static_ip,
            1 => [settings.subnet_prefix, 0, 0, 0],
            2 => settings.gateway,
            3 => settings.dns_primary,
            _ => [0; 4],
        };
        let formatted = if next == 1 {
            let mut s = [0u8; 16];
            let flen = format_prefix_buf(&mut s, value[0]);
            (s, flen)
        } else {
            let mut s = [0u8; 16];
            let flen = format_ip_buf(&mut s, &value);
            (s, flen)
        };
        buf[next] = formatted.0;
        lens[next] = formatted.1;
    } else if (ch.is_ascii_digit() || ch == b'.' || ch == b'/') && len < 15 {
        buf[field][len] = ch;
        lens[field] = (len + 1) as u8;
    }

    true
}

fn parse_ip_field(input: &[u8], field: u8) -> Option<[u8; 4]> {
    if field == 1 {
        let s = core::str::from_utf8(input).ok()?;
        let s = s.trim_start_matches('/');
        let prefix: u8 = s.parse().ok()?;
        if prefix <= 32 {
            return Some([prefix, 0, 0, 0]);
        }
        return None;
    }

    let s = core::str::from_utf8(input).ok()?;
    let mut octets = [0u8; 4];
    let mut idx = 0;
    for part in s.split('.') {
        if idx >= 4 {
            return None;
        }
        octets[idx] = part.parse().ok()?;
        idx += 1;
    }
    if idx == 4 {
        Some(octets)
    } else {
        None
    }
}

fn format_ip_buf(buf: &mut [u8; 16], ip: &[u8; 4]) -> u8 {
    let mut idx = 0;
    for (i, &octet) in ip.iter().enumerate() {
        if octet >= 100 {
            buf[idx] = b'0' + (octet / 100);
            idx += 1;
        }
        if octet >= 10 {
            buf[idx] = b'0' + ((octet / 10) % 10);
            idx += 1;
        }
        buf[idx] = b'0' + (octet % 10);
        idx += 1;
        if i < 3 {
            buf[idx] = b'.';
            idx += 1;
        }
    }
    idx as u8
}

fn format_prefix_buf(buf: &mut [u8; 16], prefix: u8) -> u8 {
    let mut idx = 0;
    buf[idx] = b'/';
    idx += 1;
    if prefix >= 10 {
        buf[idx] = b'0' + (prefix / 10);
        idx += 1;
    }
    buf[idx] = b'0' + (prefix % 10);
    idx += 1;
    idx as u8
}
