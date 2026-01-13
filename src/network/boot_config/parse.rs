// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::config::{configure, get_config, CONFIG_LOCKED};
use super::types::{DnsMode, PrivacyMode};

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

        let key = parts[0];
        let value = parts[1];
        match key {
            "nonos.privacy" => match value {
                "standard" => {
                    config.privacy_mode = PrivacyMode::Standard;
                    config.onion.enabled = false;
                    crate::log::info!("net: privacy=STANDARD");
                }
                "anonymous" | "tor" => {
                    config.privacy_mode = PrivacyMode::TorOnly;
                    config.onion.enabled = true;
                    config.dns_mode = DnsMode::TorDns;
                    crate::log::info!("net: privacy=ANONYMOUS (Tor)");
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
                    crate::log::info!(
                        "net: static IP={}.{}.{}.{}",
                        ip[0],
                        ip[1],
                        ip[2],
                        ip[3]
                    );
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
                    crate::log::info!(
                        "net: DNS={}.{}.{}.{}",
                        dns[0],
                        dns[1],
                        dns[2],
                        dns[3]
                    );
                }
            }

            "nonos.dns_mode" => match value {
                "dhcp" => {
                    config.dns_mode = DnsMode::Dhcp;
                    crate::log::info!("net: DNS mode=DHCP");
                }
                "tor" => {
                    config.dns_mode = DnsMode::TorDns;
                    crate::log::info!("net: DNS mode=Tor (anonymized)");
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

            "nonos.tor" => match value {
                "on" | "yes" | "1" | "true" => {
                    config.onion.enabled = true;
                    config.onion.auto_connect = true;
                    crate::log::info!("net: Tor=ENABLED");
                }
                "off" | "no" | "0" | "false" => {
                    config.onion.enabled = false;
                    config.onion.auto_connect = false;
                    crate::log::info!("net: Tor=DISABLED");
                }
                _ => crate::log_warn!("net: invalid tor value: {}", value),
            },

            "nonos.tor_circuits" => {
                if let Ok(n) = value.parse::<u8>() {
                    config.onion.prebuild_circuits = n.min(10);
                    crate::log::info!("net: Tor circuits={}", config.onion.prebuild_circuits);
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

/// Parse IPv4 address string (e.g., "10.0.2.15")
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        match part.parse::<u8>() {
            Ok(n) => ip[i] = n,
            Err(_) => return None,
        }
    }
    Some(ip)
}

/// *** initialize network configuration from boot handoff *** ///
pub fn init_from_handoff() {
    use crate::boot::handoff::get_handoff;
    if let Some(handoff) = get_handoff() {
        if let Some(cmdline) = unsafe { handoff.cmdline() } {
            crate::log::info!("net: found boot cmdline: {}", cmdline);
            parse_cmdline(cmdline);
        } else {
            crate::log::info!("net: no cmdline, using default config");
        }
    }
}

pub fn export_as_cmdline() -> String {
    let mut cmd = String::new();
    if let Some(config) = get_config() {
        let privacy = match config.privacy_mode {
            PrivacyMode::Standard => "standard",
            PrivacyMode::TorOnly => "anonymous",
            PrivacyMode::Maximum => "maximum",
            PrivacyMode::Isolated => "isolated",
        };
        cmd.push_str(&alloc::format!("nonos.privacy={} ", privacy));

        if !config.ipv4.use_dhcp {
            cmd.push_str(&alloc::format!(
                "nonos.ip={}.{}.{}.{}/{} ",
                config.ipv4.address[0],
                config.ipv4.address[1],
                config.ipv4.address[2],
                config.ipv4.address[3],
                config.ipv4.prefix
            ));

            if let Some(gw) = config.ipv4.gateway {
                cmd.push_str(&alloc::format!(
                    "nonos.gateway={}.{}.{}.{} ",
                    gw[0], gw[1], gw[2], gw[3]
                ));
            }
        } else {
            cmd.push_str("nonos.dhcp=on ");
        }

        let dns_mode = match config.dns_mode {
            DnsMode::Dhcp => "dhcp",
            DnsMode::Custom(_) => "custom",
            DnsMode::TorDns => "tor",
            DnsMode::DoH => "doh",
            DnsMode::None => "none",
        };
        cmd.push_str(&alloc::format!("nonos.dns_mode={} ", dns_mode));
       
        if config.onion.enabled {
            cmd.push_str("nonos.tor=on ");
            cmd.push_str(&alloc::format!(
                "nonos.tor_circuits={} ",
                config.onion.prebuild_circuits
            ));
        } else {
            cmd.push_str("nonos.tor=off ");
        }

        if config.randomize_mac {
            cmd.push_str("nonos.mac_random=on ");
        }

        if !config.hostname.is_empty() {
            cmd.push_str(&alloc::format!("nonos.hostname={} ", config.hostname));
        }
    }

    cmd.trim().to_string()
}
