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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Mutex;
use crate::drivers::wifi::ScanResult;
use crate::sys::settings::network as net_settings;
use crate::graphics::window::settings::state::SETTING_DHCP_ENABLED;

pub static WIFI_SCANNING: AtomicBool = AtomicBool::new(false);
pub static SELECTED_NETWORK: AtomicU8 = AtomicU8::new(255);
pub static SHOW_PASSWORD_DIALOG: AtomicBool = AtomicBool::new(false);
pub static CACHED_SCAN_RESULTS: Mutex<Vec<ScanResult>> = Mutex::new(Vec::new());
pub static PASSWORD_BUFFER: Mutex<[u8; 64]> = Mutex::new([0u8; 64]);
pub static PASSWORD_LEN: AtomicU8 = AtomicU8::new(0);
pub static CONNECTING: AtomicBool = AtomicBool::new(false);
pub static CONNECTION_ERROR: Mutex<Option<&'static str>> = Mutex::new(None);
pub static LOADING_FIRMWARE: AtomicBool = AtomicBool::new(false);

pub static STATIC_IP_EDITING: AtomicBool = AtomicBool::new(false);
pub static STATIC_IP_FIELD: AtomicU8 = AtomicU8::new(0);
pub static STATIC_IP_BUFFER: Mutex<[[u8; 16]; 4]> = Mutex::new([[0u8; 16]; 4]);
pub static STATIC_IP_LENS: Mutex<[u8; 4]> = Mutex::new([0u8; 4]);

pub(crate) fn sync_from_system() {
    let settings = net_settings::get_settings();
    SETTING_DHCP_ENABLED.store(settings.dhcp_enabled, Ordering::Relaxed);

    /* sync static IP fields from saved settings */
    if !settings.dhcp_enabled {
        let mut buffers = STATIC_IP_BUFFER.lock();
        let mut lens = STATIC_IP_LENS.lock();

        if settings.static_ip != [0, 0, 0, 0] {
            let ip_str = format_ipv4(&settings.static_ip);
            let l = ip_str.len().min(15);
            buffers[0][..l].copy_from_slice(&ip_str[..l]);
            lens[0] = l as u8;
        }

        if settings.gateway != [0, 0, 0, 0] {
            let gw_str = format_ipv4(&settings.gateway);
            let l = gw_str.len().min(15);
            buffers[1][..l].copy_from_slice(&gw_str[..l]);
            lens[1] = l as u8;
        }

        if settings.dns_primary != [0, 0, 0, 0] {
            let dns_str = format_ipv4(&settings.dns_primary);
            let l = dns_str.len().min(15);
            buffers[2][..l].copy_from_slice(&dns_str[..l]);
            lens[2] = l as u8;
        }
    }
}

fn format_ipv4(ip: &[u8; 4]) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let mut pos = 0;

    for (i, &octet) in ip.iter().enumerate() {
        if i > 0 {
            buf[pos] = b'.';
            pos += 1;
        }
        if octet >= 100 {
            buf[pos] = b'0' + (octet / 100);
            pos += 1;
        }
        if octet >= 10 {
            buf[pos] = b'0' + ((octet / 10) % 10);
            pos += 1;
        }
        buf[pos] = b'0' + (octet % 10);
        pos += 1;
    }
    buf
}
