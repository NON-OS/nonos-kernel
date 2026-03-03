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

use super::config::configure;
use super::types::{
    DnsMode, FirewallConfig, Ipv4Config, NetworkBootConfig, OnionConfig, PrivacyMode,
};

pub fn preset_standard() {
    if let Some(mut config) = configure() {
        *config = NetworkBootConfig {
            privacy_mode: PrivacyMode::Standard,
            ipv4: Ipv4Config {
                use_dhcp: true,
                ..Default::default()
            },
            dns_mode: DnsMode::Dhcp,
            onion: OnionConfig {
                enabled: false,
                ..Default::default()
            },
            firewall: FirewallConfig {
                block_inbound: true,
                allow_outbound: true,
                log_connections: false,
                ..Default::default()
            },
            randomize_mac: false,
            ..Default::default()
        };
        crate::log::info!("net: applied STANDARD preset");
    }
}

pub fn preset_anonymous() {
    if let Some(mut config) = configure() {
        *config = NetworkBootConfig {
            privacy_mode: PrivacyMode::TorOnly,
            ipv4: Ipv4Config {
                use_dhcp: true,
                ..Default::default()
            },
            dns_mode: DnsMode::TorDns,
            onion: OnionConfig {
                enabled: true,
                auto_connect: true,
                prebuild_circuits: 5,
                relay_mode: false,
                strict_exit: true,
                ..Default::default()
            },
            firewall: FirewallConfig {
                block_inbound: true,
                allow_outbound: true,
                allowed_ports: alloc::vec![443, 9001, 9030, 9050, 9051],
                log_connections: true,
                rate_limit: 500,
                ..Default::default()
            },
            randomize_mac: true,
            hostname: String::new(),
            ..Default::default()
        };
        crate::log::info!("net: applied ANONYMOUS preset");
    }
}

pub fn preset_maximum() {
    if let Some(mut config) = configure() {
        *config = NetworkBootConfig {
            privacy_mode: PrivacyMode::Maximum,
            ipv4: Ipv4Config {
                use_dhcp: true,
                ..Default::default()
            },
            dns_mode: DnsMode::TorDns,
            onion: OnionConfig {
                enabled: true,
                auto_connect: true,
                prebuild_circuits: 7,
                relay_mode: false,
                strict_exit: true,
                block_hidden_services: false,
                ..Default::default()
            },
            firewall: FirewallConfig {
                block_inbound: true,
                allow_outbound: true,
                allowed_ports: alloc::vec![443, 9001],
                log_connections: true,
                rate_limit: 100,
                ..Default::default()
            },
            randomize_mac: true,
            hostname: String::new(),
            ..Default::default()
        };
        crate::log::info!("net: applied MAXIMUM PRIVACY preset");
    }
}

pub fn preset_isolated() {
    if let Some(mut config) = configure() {
        *config = NetworkBootConfig {
            privacy_mode: PrivacyMode::Isolated,
            ipv4: Ipv4Config {
                use_dhcp: false,
                address: [0, 0, 0, 0],
                ..Default::default()
            },
            dns_mode: DnsMode::None,
            onion: OnionConfig {
                enabled: false,
                ..Default::default()
            },
            firewall: FirewallConfig {
                block_inbound: true,
                allow_outbound: false,
                ..Default::default()
            },
            randomize_mac: true,
            ..Default::default()
        };
        crate::log::info!("net: applied ISOLATED preset (air-gapped)");
    }
}
