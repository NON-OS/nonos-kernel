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
use super::super::config::{configure, CONFIG_LOCKED};
use super::super::types::{DnsMode, PrivacyMode};
use super::utils::parse_ipv4;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

pub fn parse_cmdline(cmdline: &str) {
    if CONFIG_LOCKED.load(Ordering::SeqCst) {
        crate::log_warn!("net: config locked, ignoring cmdline");
        return;
    }
    let mut config = match configure() {
        Some(c) => c,
        None => return,
    };
    crate::log::info!("net: parsing boot parameters...");
    for param in cmdline.split_whitespace() {
        if !param.starts_with("nonos.") {
            continue;
        }
        let parts: Vec<&str> = param.splitn(2, '=').collect();
        if parts.len() != 2 {
            continue;
        }
        let (key, value) = (parts[0], parts[1]);
        match key {
            "nonos.privacy" => match value {
                "standard" => {
                    config.privacy_mode = PrivacyMode::Standard;
                    config.onion.enabled = false;
                    crate::log::info!("net: privacy=STANDARD");
                }
                "anonymous" | "nym" | "mixnet" => {
                    config.privacy_mode = PrivacyMode::TorOnly;
                    config.onion.enabled = true;
                    config.dns_mode = DnsMode::TorDns;
                    crate::log::info!("net: privacy=ANONYMOUS (NYM Mixnet)");
                }
                "maximum" | "paranoid" => {
                    config.privacy_mode = PrivacyMode::Maximum;
                    config.onion.enabled = true;
                    config.dns_mode = DnsMode::TorDns;
                    config.firewall.allowed_ports = alloc::vec![443, 9001];
                    crate::log::info!("net: privacy=MAXIMUM");
                }
                "isolated" | "airgap" | "off" => {
                    config.privacy_mode = PrivacyMode::Isolated;
                    config.onion.enabled = false;
                    config.dns_mode = DnsMode::None;
                    crate::log::info!("net: privacy=ISOLATED (no network)");
                }
                _ => crate::log_warn!("net: unknown privacy mode: {}", value),
            },
            "nonos.ip" => {
                if let Some((ip_str, prefix_str)) = value.split_once('/') {
                    if let Some(ip) = parse_ipv4(ip_str) {
                        config.ipv4.address = ip;
                        config.ipv4.use_dhcp = false;
                        if let Ok(prefix) = prefix_str.parse::<u8>() {
                            config.ipv4.prefix = prefix;
                        }
                        crate::log::info!(
                            "net: static IP={}.{}.{}.{}/{}",
                            ip[0],
                            ip[1],
                            ip[2],
                            ip[3],
                            config.ipv4.prefix
                        );
                    }
                } else if let Some(ip) = parse_ipv4(value) {
                    config.ipv4.address = ip;
                    config.ipv4.use_dhcp = false;
                    crate::log::info!("net: static IP={}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                }
            }
            "nonos.gateway" | "nonos.gw" => {
                if let Some(gw) = parse_ipv4(value) {
                    config.ipv4.gateway = Some(gw);
                    crate::log::info!("net: gateway={}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
                }
            }
            "nonos.dns" => {
                if let Some(dns) = parse_ipv4(value) {
                    config.dns_mode = DnsMode::Custom(dns);
                    config.dns_servers.push(dns);
                    crate::log::info!("net: DNS={}.{}.{}.{}", dns[0], dns[1], dns[2], dns[3]);
                }
            }
            "nonos.dns_mode" => match value {
                "dhcp" => {
                    config.dns_mode = DnsMode::Dhcp;
                    crate::log::info!("net: DNS mode=DHCP");
                }
                "nym" | "mixnet" => {
                    config.dns_mode = DnsMode::TorDns;
                    crate::log::info!("net: DNS mode=NYM (anonymized)");
                }
                "doh" | "https" => {
                    config.dns_mode = DnsMode::DoH;
                    crate::log::info!("net: DNS mode=DoH (encrypted)");
                }
                "none" | "off" => {
                    config.dns_mode = DnsMode::None;
                    crate::log::info!("net: DNS mode=NONE");
                }
                _ => crate::log_warn!("net: unknown DNS mode: {}", value),
            },
            "nonos.nym" | "nonos.mixnet" => match value {
                "on" | "yes" | "1" | "true" => {
                    config.onion.enabled = true;
                    config.onion.auto_connect = true;
                    crate::log::info!("net: NYM Mixnet=ENABLED");
                }
                "off" | "no" | "0" | "false" => {
                    config.onion.enabled = false;
                    config.onion.auto_connect = false;
                    crate::log::info!("net: NYM Mixnet=DISABLED");
                }
                _ => crate::log_warn!("net: invalid nym value: {}", value),
            },
            "nonos.nym_gateways" => {
                if let Ok(n) = value.parse::<u8>() {
                    config.onion.prebuild_circuits = n.min(10);
                    crate::log::info!("net: NYM gateways={}", config.onion.prebuild_circuits);
                }
            }
            "nonos.firewall" => match value {
                "strict" => {
                    config.firewall.block_inbound = true;
                    config.firewall.allow_outbound = true;
                    config.firewall.allowed_ports = alloc::vec![443, 9001];
                    config.firewall.log_connections = true;
                    crate::log::info!("net: firewall=STRICT");
                }
                "normal" => {
                    config.firewall.block_inbound = true;
                    config.firewall.allow_outbound = true;
                    config.firewall.allowed_ports = Vec::new();
                    crate::log::info!("net: firewall=NORMAL");
                }
                "off" | "disabled" => {
                    config.firewall.block_inbound = false;
                    config.firewall.allow_outbound = true;
                    crate::log::info!("net: firewall=OFF");
                }
                _ => crate::log_warn!("net: unknown firewall mode: {}", value),
            },
            "nonos.mac_random" => match value {
                "on" | "yes" | "1" | "true" => {
                    config.randomize_mac = true;
                    crate::log::info!("net: MAC randomization=ON");
                }
                "off" | "no" | "0" | "false" => {
                    config.randomize_mac = false;
                    crate::log::info!("net: MAC randomization=OFF");
                }
                _ => {}
            },
            "nonos.hostname" => {
                config.hostname = String::from(value);
                crate::log::info!("net: hostname={}", value);
            }
            "nonos.dhcp" => match value {
                "on" | "yes" | "1" | "true" => {
                    config.ipv4.use_dhcp = true;
                    crate::log::info!("net: DHCP=ON");
                }
                "off" | "no" | "0" | "false" => {
                    config.ipv4.use_dhcp = false;
                    crate::log::info!("net: DHCP=OFF");
                }
                _ => {}
            },
            _ => {}
        }
    }
    crate::log::info!("net: boot parameters parsed");
}
