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

use super::config::{get_config, is_locked};

pub fn get_status() -> String {
    let mut status = String::new();

    if let Some(config) = get_config() {
        status.push_str("=== NONOS Network Status ===\n");
        status.push_str(&alloc::format!("Privacy Mode: {:?}\n", config.privacy_mode));
        status.push_str(&alloc::format!("Config Locked: {}\n", is_locked()));

        if config.ipv4.use_dhcp {
            status.push_str("IPv4: DHCP\n");
        } else {
            status.push_str(&alloc::format!(
                "IPv4: {}.{}.{}.{}/{}\n",
                config.ipv4.address[0],
                config.ipv4.address[1],
                config.ipv4.address[2],
                config.ipv4.address[3],
                config.ipv4.prefix
            ));
        }

        status.push_str(&alloc::format!("DNS Mode: {:?}\n", config.dns_mode));

        if config.onion.enabled {
            status.push_str("Anyone.io: ENABLED\n");
            status.push_str(&alloc::format!(
                "  Auto-connect: {}\n",
                config.onion.auto_connect
            ));
            status.push_str(&alloc::format!("  Relay mode: {}\n", config.onion.relay_mode));
        } else {
            status.push_str("Anyone.io: DISABLED\n");
        }

        status.push_str(&alloc::format!(
            "Firewall: inbound={}, outbound={}\n",
            if config.firewall.block_inbound {
                "BLOCKED"
            } else {
                "ALLOWED"
            },
            if config.firewall.allow_outbound {
                "ALLOWED"
            } else {
                "BLOCKED"
            }
        ));

        status.push_str(&alloc::format!(
            "MAC Randomization: {}\n",
            config.randomize_mac
        ));
    } else {
        status.push_str("Network boot config not initialized\n");
    }

    status
}

pub fn print_status() {
    let status = get_status();
    for line in status.lines() {
        crate::log::info!("{}", line);
    }
}
