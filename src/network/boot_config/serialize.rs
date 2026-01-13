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

use core::sync::atomic::Ordering;

use super::config::{configure, get_config, CONFIG_LOCKED};
use super::types::{DnsMode, PrivacyMode};
/// Serialize configuration to binary format for session persistence
/// This returns a fixed-size binary blob that can be stored in memory
pub fn serialize_config() -> Option<[u8; 256]> {
    let config = get_config()?;
    let mut buf = [0u8; 256];
    // Magic header "NNCF"
    buf[0..4].copy_from_slice(b"NNCF");
    // Version
    buf[4] = 1;
    // Privacy mode
    buf[5] = config.privacy_mode as u8;
    // IPv4 config
    buf[6..10].copy_from_slice(&config.ipv4.address);
    buf[10] = config.ipv4.prefix;
    buf[11] = if config.ipv4.use_dhcp { 1 } else { 0 };
    if let Some(gw) = config.ipv4.gateway {
        buf[12..16].copy_from_slice(&gw);
    }

    // DNS mode
    buf[16] = match config.dns_mode {
        DnsMode::Dhcp => 0,
        DnsMode::Custom(_) => 1,
        DnsMode::TorDns => 2,
        DnsMode::DoH => 3,
        DnsMode::None => 4,
    };

    // Onion config
    buf[17] = if config.onion.enabled { 1 } else { 0 };
    buf[18] = if config.onion.auto_connect { 1 } else { 0 };
    buf[19] = config.onion.prebuild_circuits;
    // Firewall config
    buf[20] = if config.firewall.block_inbound { 1 } else { 0 };
    buf[21] = if config.firewall.allow_outbound { 1 } else { 0 };
    buf[22] = if config.firewall.log_connections { 1 } else { 0 };
    // MAC randomization
    buf[23] = if config.randomize_mac { 1 } else { 0 };
    // Boot time (8 bytes)
    buf[24..32].copy_from_slice(&config.boot_time.to_le_bytes());

    Some(buf)
}

/// Deserialize configuration from binary format
pub fn deserialize_config(buf: &[u8; 256]) -> Result<(), &'static str> {
    if CONFIG_LOCKED.load(Ordering::SeqCst) {
        return Err("Config is locked");
    }

    // Check magic header
    if &buf[0..4] != b"NNCF" {
        return Err("Invalid config magic");
    }

    // Check version
    if buf[4] != 1 {
        return Err("Unsupported config version");
    }

    let mut config = configure().ok_or("Config not initialized")?;

    // Privacy mode
    config.privacy_mode = PrivacyMode::from(buf[5]);

    // IPv4 config
    config.ipv4.address.copy_from_slice(&buf[6..10]);
    config.ipv4.prefix = buf[10];
    config.ipv4.use_dhcp = buf[11] != 0;
    if buf[12..16] != [0, 0, 0, 0] {
        let mut gw = [0u8; 4];
        gw.copy_from_slice(&buf[12..16]);
        config.ipv4.gateway = Some(gw);
    }

    // DNS mode
    config.dns_mode = match buf[16] {
        0 => DnsMode::Dhcp,
        1 => DnsMode::Custom([0, 0, 0, 0]),
        2 => DnsMode::TorDns,
        3 => DnsMode::DoH,
        _ => DnsMode::None,
    };

    // Onion config
    config.onion.enabled = buf[17] != 0;
    config.onion.auto_connect = buf[18] != 0;
    config.onion.prebuild_circuits = buf[19];
    // Firewall config
    config.firewall.block_inbound = buf[20] != 0;
    config.firewall.allow_outbound = buf[21] != 0;
    config.firewall.log_connections = buf[22] != 0;
    // MAC randomization
    config.randomize_mac = buf[23] != 0;
    // Boot time
    let mut time_bytes = [0u8; 8];
    time_bytes.copy_from_slice(&buf[24..32]);
    config.boot_time = u64::from_le_bytes(time_bytes);

    crate::log::info!("net: restored config from binary");
    Ok(())
}
