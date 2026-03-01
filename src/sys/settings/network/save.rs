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
use crate::storage::fat32;
use super::state::{SAVED_NETWORKS, SETTINGS_MODIFIED};
use super::api::get_settings;
use super::serialize::serialize_settings;
use super::block::{block_read, block_write};

pub const NETWORK_SETTINGS_FILENAME: &[u8] = b"NETWORK.CFG";
pub const WIFI_NETWORKS_FILENAME: &[u8] = b"WIFI.CFG";

pub fn save_to_disk() -> bool {
    if !SETTINGS_MODIFIED.load(Ordering::Relaxed) {
        return true;
    }

    if fat32::fs_count() == 0 {
        return false;
    }

    let fs = match fat32::get_fs(0) {
        Some(f) => f,
        None => return false,
    };

    let _settings = get_settings();
    let mut buf = [0u8; 2048];
    let len = serialize_settings(&mut buf);

    let saved_main = match fat32::find_file(&fs, NETWORK_SETTINGS_FILENAME, block_read) {
        Ok(Some(mut entry)) => {
            fat32::update_file(&fs, &mut entry, fs.root_cluster, &buf[..len], block_read, block_write).is_ok()
        }
        Ok(None) => {
            fat32::create_file(&fs, fs.root_cluster, NETWORK_SETTINGS_FILENAME, &buf[..len], block_read, block_write).is_ok()
        }
        Err(_) => false,
    };

    let saved_wifi = save_wifi_networks(&fs);

    if saved_main {
        SETTINGS_MODIFIED.store(false, Ordering::SeqCst);
    }

    saved_main && saved_wifi
}

fn save_wifi_networks(fs: &fat32::Fat32) -> bool {
    let networks = SAVED_NETWORKS.lock();
    if networks.is_empty() {
        return true;
    }

    let mut buf = [0u8; 4096];
    let mut pos = 0;

    for network in networks.iter() {
        for ch in network.ssid.bytes() {
            if pos < buf.len() { buf[pos] = ch; pos += 1; }
        }
        if pos < buf.len() { buf[pos] = b'|'; pos += 1; }

        for _ in 0..12 {
            if pos < buf.len() { buf[pos] = b'0'; pos += 1; }
        }
        if pos < buf.len() { buf[pos] = b'|'; pos += 1; }

        let sec_str: &[u8] = match network.security {
            0 => b"OPEN__",
            1 => b"WEP___",
            2 => b"WPA___",
            3 => b"WPA2__",
            4 => b"WPA3__",
            _ => b"UNKNWN",
        };
        for &ch in sec_str { if pos < buf.len() { buf[pos] = ch; pos += 1; } }
        if pos < buf.len() { buf[pos] = b'|'; pos += 1; }

        for &ch in &network.password_encrypted[..64] {
            let hi = if ch >> 4 > 9 { b'A' + (ch >> 4) - 10 } else { b'0' + (ch >> 4) };
            let lo = if ch & 0xF > 9 { b'A' + (ch & 0xF) - 10 } else { b'0' + (ch & 0xF) };
            if pos < buf.len() { buf[pos] = hi; pos += 1; }
            if pos < buf.len() { buf[pos] = lo; pos += 1; }
        }
        if pos < buf.len() { buf[pos] = b'\n'; pos += 1; }
    }

    drop(networks);

    if pos == 0 {
        return true;
    }

    match fat32::find_file(fs, WIFI_NETWORKS_FILENAME, block_read) {
        Ok(Some(mut entry)) => {
            fat32::update_file(fs, &mut entry, fs.root_cluster, &buf[..pos], block_read, block_write).is_ok()
        }
        Ok(None) => {
            fat32::create_file(fs, fs.root_cluster, WIFI_NETWORKS_FILENAME, &buf[..pos], block_read, block_write).is_ok()
        }
        Err(_) => false,
    }
}
