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

use alloc::string::String;
use crate::network::boot_config::PrivacyMode;

pub const MAX_SAVED_NETWORKS: usize = 16;
pub const MAX_PASSWORD_LEN: usize = 64;

#[derive(Clone)]
pub struct SavedNetwork {
    pub ssid: String,
    pub password_encrypted: [u8; MAX_PASSWORD_LEN],
    pub password_len: u8,
    pub security: u8,
    pub priority: u8,
    pub last_connected: u64,
    pub connect_count: u32,
}

impl Default for SavedNetwork {
    fn default() -> Self {
        Self {
            ssid: String::new(),
            password_encrypted: [0u8; MAX_PASSWORD_LEN],
            password_len: 0,
            security: 0,
            priority: 255,
            last_connected: 0,
            connect_count: 0,
        }
    }
}

#[derive(Clone)]
pub struct NetworkSettings {
    pub privacy_mode: PrivacyMode,
    pub dhcp_enabled: bool,
    pub static_ip: [u8; 4],
    pub subnet_prefix: u8,
    pub gateway: [u8; 4],
    pub dns_primary: [u8; 4],
    pub dns_secondary: [u8; 4],
    pub dns_over_onion: bool,
    pub onion_enabled: bool,
    pub onion_auto_connect: bool,
    pub onion_prebuild_circuits: u8,
    pub onion_relay_mode: bool,
    pub socks_enabled: bool,
    pub socks_port: u16,
    pub transparent_proxy: bool,
    pub strict_onion: bool,
    pub randomize_mac: bool,
    pub firewall_enabled: bool,
    pub block_inbound: bool,
    pub log_connections: bool,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            privacy_mode: PrivacyMode::TorOnly,
            dhcp_enabled: true,
            static_ip: [0, 0, 0, 0],
            subnet_prefix: 24,
            gateway: [0, 0, 0, 0],
            dns_primary: [8, 8, 8, 8],
            dns_secondary: [8, 8, 4, 4],
            dns_over_onion: true,
            onion_enabled: true,
            onion_auto_connect: true,
            onion_prebuild_circuits: 3,
            onion_relay_mode: false,
            socks_enabled: true,
            socks_port: 9050,
            transparent_proxy: true,
            strict_onion: true,
            randomize_mac: true,
            firewall_enabled: true,
            block_inbound: true,
            log_connections: true,
        }
    }
}
