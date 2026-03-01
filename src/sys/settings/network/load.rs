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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use crate::storage::fat32;
use super::types::MAX_PASSWORD_LEN;
use super::state::SETTINGS_MODIFIED;
use super::wifi::save_wifi_network;
use super::serialize::deserialize_settings;
use super::helpers::{decrypt_password, hex_char_value};
use super::block::block_read;
use super::save::{NETWORK_SETTINGS_FILENAME, WIFI_NETWORKS_FILENAME};

pub fn load_from_disk() -> bool {
    if fat32::fs_count() == 0 {
        return false;
    }

    let fs = match fat32::get_fs(0) {
        Some(f) => f,
        None => return false,
    };

    let loaded_main = match fat32::find_file(&fs, NETWORK_SETTINGS_FILENAME, block_read) {
        Ok(Some(entry)) => {
            let mut buf = [0u8; 2048];
            match fat32::read_file(&fs, &entry, &mut buf, block_read) {
                Ok(bytes_read) if bytes_read > 0 => {
                    deserialize_settings(&buf[..bytes_read]);
                    true
                }
                _ => false,
            }
        }
        _ => false,
    };

    let loaded_wifi = load_wifi_networks(&fs);

    if loaded_main {
        SETTINGS_MODIFIED.store(false, Ordering::SeqCst);
    }

    loaded_main || loaded_wifi
}

fn load_wifi_networks(fs: &fat32::Fat32) -> bool {
    let entry = match fat32::find_file(fs, WIFI_NETWORKS_FILENAME, block_read) {
        Ok(Some(e)) => e,
        _ => return false,
    };

    let mut buf = [0u8; 4096];
    let bytes_read = match fat32::read_file(fs, &entry, &mut buf, block_read) {
        Ok(n) if n > 0 => n,
        _ => return false,
    };

    let mut line_start = 0;
    while line_start < bytes_read {
        let mut line_end = line_start;
        while line_end < bytes_read && buf[line_end] != b'\n' {
            line_end += 1;
        }

        if line_end > line_start {
            let _ = parse_wifi_network_line(&buf[line_start..line_end]);
        }

        line_start = line_end + 1;
    }

    true
}

fn parse_wifi_network_line(line: &[u8]) -> Option<()> {
    let parts: Vec<&[u8]> = line.split(|&c| c == b'|').collect();
    if parts.len() < 4 {
        return None;
    }

    let ssid = parts[0];
    let security_str = parts[2];
    let password_hex = parts[3];

    let mut ssid_buf = [0u8; 32];
    let ssid_len = ssid.len().min(32);
    ssid_buf[..ssid_len].copy_from_slice(&ssid[..ssid_len]);

    let security = if security_str == b"OPEN" { 0u8 }
    else if security_str == b"WEP" { 1u8 }
    else if security_str == b"WPA" { 2u8 }
    else if security_str == b"WPA2" { 3u8 }
    else if security_str == b"WPA3" { 4u8 }
    else { 0u8 };

    let mut password_encrypted = [0u8; MAX_PASSWORD_LEN];
    let pwd_len = (password_hex.len() / 2).min(MAX_PASSWORD_LEN);
    for i in 0..pwd_len {
        let hi = hex_char_value(password_hex[i * 2]);
        let lo = hex_char_value(password_hex[i * 2 + 1]);
        password_encrypted[i] = (hi << 4) | lo;
    }

    let mut password_plaintext = [0u8; MAX_PASSWORD_LEN];
    decrypt_password(&password_encrypted, &mut password_plaintext);

    let password_len = password_plaintext.iter().position(|&c| c == 0).unwrap_or(MAX_PASSWORD_LEN);
    let password_str = core::str::from_utf8(&password_plaintext[..password_len]).ok()?;
    let ssid_str = core::str::from_utf8(&ssid_buf[..ssid_len]).ok()?;

    let _ = save_wifi_network(ssid_str, password_str, security);
    Some(())
}
