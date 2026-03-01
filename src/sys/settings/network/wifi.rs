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

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use super::types::{SavedNetwork, MAX_SAVED_NETWORKS, MAX_PASSWORD_LEN};
use super::state::{SAVED_NETWORKS, SETTINGS_MODIFIED};
use super::helpers::{encrypt_password, decrypt_password};

pub fn save_wifi_network(ssid: &str, password: &str, security: u8) -> Result<(), &'static str> {
    let mut networks = SAVED_NETWORKS.lock();

    if let Some(existing) = networks.iter_mut().find(|n| n.ssid == ssid) {
        encrypt_password(password.as_bytes(), &mut existing.password_encrypted);
        existing.password_len = password.len().min(MAX_PASSWORD_LEN) as u8;
        existing.security = security;
        existing.last_connected = crate::time::timestamp_millis();
        existing.connect_count += 1;
    } else {
        if networks.len() >= MAX_SAVED_NETWORKS {
            if let Some((idx, _)) = networks.iter().enumerate().max_by_key(|(_, n)| n.priority) {
                networks.remove(idx);
            }
        }

        let mut entry = SavedNetwork::default();
        entry.ssid = ssid.to_string();
        encrypt_password(password.as_bytes(), &mut entry.password_encrypted);
        entry.password_len = password.len().min(MAX_PASSWORD_LEN) as u8;
        entry.security = security;
        entry.priority = networks.len() as u8;
        entry.last_connected = crate::time::timestamp_millis();
        entry.connect_count = 1;

        networks.push(entry);
    }

    SETTINGS_MODIFIED.store(true, Ordering::SeqCst);
    Ok(())
}

pub fn get_saved_networks() -> Vec<(String, u8)> {
    SAVED_NETWORKS
        .lock()
        .iter()
        .map(|n| (n.ssid.clone(), n.security))
        .collect()
}

pub fn get_saved_password(ssid: &str) -> Option<String> {
    let networks = SAVED_NETWORKS.lock();
    networks.iter().find(|n| n.ssid == ssid).map(|n| {
        let mut decrypted = [0u8; MAX_PASSWORD_LEN];
        decrypt_password(&n.password_encrypted, &mut decrypted);
        String::from_utf8_lossy(&decrypted[..n.password_len as usize]).into_owned()
    })
}

pub fn remove_saved_network(ssid: &str) -> bool {
    let mut networks = SAVED_NETWORKS.lock();
    if let Some(idx) = networks.iter().position(|n| n.ssid == ssid) {
        networks.remove(idx);
        SETTINGS_MODIFIED.store(true, Ordering::SeqCst);
        true
    } else {
        false
    }
}

pub fn set_network_priority(ssid: &str, priority: u8) {
    let mut networks = SAVED_NETWORKS.lock();
    if let Some(network) = networks.iter_mut().find(|n| n.ssid == ssid) {
        network.priority = priority;
        SETTINGS_MODIFIED.store(true, Ordering::SeqCst);
    }
}
