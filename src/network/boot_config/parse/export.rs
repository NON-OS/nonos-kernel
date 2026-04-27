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
use super::super::config::get_config;
use super::super::types::{DnsMode, PrivacyMode};
use alloc::string::{String, ToString};

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
                    gw[0],
                    gw[1],
                    gw[2],
                    gw[3]
                ));
            }
        } else {
            cmd.push_str("nonos.dhcp=on ");
        }
        let dns_mode = match config.dns_mode {
            DnsMode::Dhcp => "dhcp",
            DnsMode::Custom(_) => "custom",
            DnsMode::TorDns => "nym",
            DnsMode::DoH => "doh",
            DnsMode::None => "none",
        };
        cmd.push_str(&alloc::format!("nonos.dns_mode={} ", dns_mode));
        if config.onion.enabled {
            cmd.push_str("nonos.nym=on ");
            cmd.push_str(&alloc::format!("nonos.nym_gateways={} ", config.onion.prebuild_circuits));
        } else {
            cmd.push_str("nonos.nym=off ");
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
