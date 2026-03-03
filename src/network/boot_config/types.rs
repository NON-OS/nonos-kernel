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

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivacyMode {
    Standard = 0,
    TorOnly = 1,
    Maximum = 2,
    Isolated = 3,
}

impl From<u8> for PrivacyMode {
    fn from(v: u8) -> Self {
        match v {
            0 => PrivacyMode::Standard,
            1 => PrivacyMode::TorOnly,
            2 => PrivacyMode::Maximum,
            3 => PrivacyMode::Isolated,
            _ => PrivacyMode::Standard,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    Dhcp,
    Custom([u8; 4]),
    TorDns,
    DoH,
    None,
}

#[derive(Debug, Clone)]
pub struct Ipv4Config {
    pub address: [u8; 4],
    pub prefix: u8,
    pub gateway: Option<[u8; 4]>,
    pub use_dhcp: bool,
}

impl Default for Ipv4Config {
    fn default() -> Self {
        Self {
            address: [0, 0, 0, 0],
            prefix: 24,
            gateway: None,
            use_dhcp: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OnionConfig {
    pub enabled: bool,
    pub auto_connect: bool,
    pub prebuild_circuits: u8,
    pub relay_mode: bool,
    pub exit_relay: bool,
    pub bridge_mode: bool,
    pub bridges: Vec<String>,
    pub strict_exit: bool,
    pub block_hidden_services: bool,
}

impl Default for OnionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_connect: true,
            prebuild_circuits: 3,
            relay_mode: false,
            exit_relay: false,
            bridge_mode: false,
            bridges: Vec::new(),
            strict_exit: true,
            block_hidden_services: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FirewallConfig {
    pub block_inbound: bool,
    pub allow_outbound: bool,
    pub allowed_ports: Vec<u16>,
    pub blocked_ranges: Vec<([u8; 4], u8)>,
    pub log_connections: bool,
    pub rate_limit: u32,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            block_inbound: true,
            allow_outbound: true,
            allowed_ports: Vec::new(),
            blocked_ranges: Vec::new(),
            log_connections: true,
            rate_limit: 1000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkBootConfig {
    pub privacy_mode: PrivacyMode,
    pub ipv4: Ipv4Config,
    pub dns_mode: DnsMode,
    pub dns_servers: Vec<[u8; 4]>,
    pub onion: OnionConfig,
    pub firewall: FirewallConfig,
    pub randomize_mac: bool,
    pub hostname: String,
    pub interface: String,
    pub boot_time: u64,
}

impl Default for NetworkBootConfig {
    fn default() -> Self {
        Self {
            privacy_mode: PrivacyMode::Standard,
            ipv4: Ipv4Config::default(),
            dns_mode: DnsMode::Dhcp,
            dns_servers: Vec::new(),
            onion: OnionConfig {
                enabled: false,
                auto_connect: false,
                ..OnionConfig::default()
            },
            firewall: FirewallConfig::default(),
            randomize_mac: false,
            hostname: String::new(),
            interface: String::from("eth0"),
            boot_time: 0,
        }
    }
}
