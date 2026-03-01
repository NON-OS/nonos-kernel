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

use crate::network::boot_config::PrivacyMode;
use super::types::NetworkSettings;
use super::state::NETWORK_SETTINGS;
use super::helpers::{parse_u8, parse_u16, parse_bool, parse_ip, format_u8, format_u16, format_ip};

pub fn serialize_settings(buf: &mut [u8]) -> usize {
    let settings = NETWORK_SETTINGS.lock();
    let mut pos = 0;

    fn write_line(buf: &mut [u8], pos: &mut usize, key: &[u8], val: &[u8]) {
        for &ch in key {
            if *pos < buf.len() { buf[*pos] = ch; *pos += 1; }
        }
        if *pos < buf.len() { buf[*pos] = b'='; *pos += 1; }
        for &ch in val {
            if *pos < buf.len() { buf[*pos] = ch; *pos += 1; }
        }
        if *pos < buf.len() { buf[*pos] = b'\n'; *pos += 1; }
    }

    fn write_u8(buf: &mut [u8], pos: &mut usize, key: &[u8], val: u8) {
        let mut num_buf = [0u8; 4];
        let len = format_u8(&mut num_buf, val);
        write_line(buf, pos, key, &num_buf[..len]);
    }

    fn write_u16(buf: &mut [u8], pos: &mut usize, key: &[u8], val: u16) {
        let mut num_buf = [0u8; 6];
        let len = format_u16(&mut num_buf, val);
        write_line(buf, pos, key, &num_buf[..len]);
    }

    fn write_bool(buf: &mut [u8], pos: &mut usize, key: &[u8], val: bool) {
        write_line(buf, pos, key, if val { b"1" } else { b"0" });
    }

    fn write_ip_line(buf: &mut [u8], pos: &mut usize, key: &[u8], ip: [u8; 4]) {
        let mut ip_buf = [0u8; 16];
        let len = format_ip(&mut ip_buf, ip);
        write_line(buf, pos, key, &ip_buf[..len]);
    }

    write_u8(buf, &mut pos, b"privacy", settings.privacy_mode as u8);
    write_bool(buf, &mut pos, b"dhcp", settings.dhcp_enabled);
    write_ip_line(buf, &mut pos, b"ip", settings.static_ip);
    write_u8(buf, &mut pos, b"prefix", settings.subnet_prefix);
    write_ip_line(buf, &mut pos, b"gateway", settings.gateway);
    write_ip_line(buf, &mut pos, b"dns1", settings.dns_primary);
    write_ip_line(buf, &mut pos, b"dns2", settings.dns_secondary);
    write_bool(buf, &mut pos, b"dns_onion", settings.dns_over_onion);
    write_bool(buf, &mut pos, b"onion", settings.onion_enabled);
    write_bool(buf, &mut pos, b"onion_auto", settings.onion_auto_connect);
    write_u8(buf, &mut pos, b"onion_circuits", settings.onion_prebuild_circuits);
    write_bool(buf, &mut pos, b"onion_relay", settings.onion_relay_mode);
    write_bool(buf, &mut pos, b"socks", settings.socks_enabled);
    write_u16(buf, &mut pos, b"socks_port", settings.socks_port);
    write_bool(buf, &mut pos, b"transparent", settings.transparent_proxy);
    write_bool(buf, &mut pos, b"strict_onion", settings.strict_onion);
    write_bool(buf, &mut pos, b"mac_random", settings.randomize_mac);
    write_bool(buf, &mut pos, b"firewall", settings.firewall_enabled);
    write_bool(buf, &mut pos, b"block_in", settings.block_inbound);
    write_bool(buf, &mut pos, b"log_conn", settings.log_connections);

    pos
}

pub fn deserialize_settings(buf: &[u8]) {
    let mut settings = NetworkSettings::default();
    let mut line_start = 0;

    while line_start < buf.len() {
        let mut line_end = line_start;
        while line_end < buf.len() && buf[line_end] != b'\n' && buf[line_end] != 0 {
            line_end += 1;
        }

        if line_end > line_start {
            parse_setting_line(&buf[line_start..line_end], &mut settings);
        }

        line_start = line_end + 1;
    }

    *NETWORK_SETTINGS.lock() = settings;
}

fn parse_setting_line(line: &[u8], settings: &mut NetworkSettings) {
    let eq_pos = match line.iter().position(|&ch| ch == b'=') {
        Some(p) => p,
        None => return,
    };

    let key = &line[..eq_pos];
    let val = &line[eq_pos + 1..];

    if key == b"privacy" {
        if let Some(v) = parse_u8(val) {
            settings.privacy_mode = PrivacyMode::from(v);
        }
    } else if key == b"dhcp" {
        settings.dhcp_enabled = parse_bool(val);
    } else if key == b"ip" {
        if let Some(ip) = parse_ip(val) {
            settings.static_ip = ip;
        }
    } else if key == b"prefix" {
        if let Some(v) = parse_u8(val) {
            settings.subnet_prefix = v;
        }
    } else if key == b"gateway" {
        if let Some(ip) = parse_ip(val) {
            settings.gateway = ip;
        }
    } else if key == b"dns1" {
        if let Some(ip) = parse_ip(val) {
            settings.dns_primary = ip;
        }
    } else if key == b"dns2" {
        if let Some(ip) = parse_ip(val) {
            settings.dns_secondary = ip;
        }
    } else if key == b"dns_onion" {
        settings.dns_over_onion = parse_bool(val);
    } else if key == b"onion" {
        settings.onion_enabled = parse_bool(val);
    } else if key == b"onion_auto" {
        settings.onion_auto_connect = parse_bool(val);
    } else if key == b"onion_circuits" {
        if let Some(v) = parse_u8(val) {
            settings.onion_prebuild_circuits = v;
        }
    } else if key == b"onion_relay" {
        settings.onion_relay_mode = parse_bool(val);
    } else if key == b"socks" {
        settings.socks_enabled = parse_bool(val);
    } else if key == b"socks_port" {
        if let Some(v) = parse_u16(val) {
            settings.socks_port = v;
        }
    } else if key == b"transparent" {
        settings.transparent_proxy = parse_bool(val);
    } else if key == b"strict_onion" {
        settings.strict_onion = parse_bool(val);
    } else if key == b"mac_random" {
        settings.randomize_mac = parse_bool(val);
    } else if key == b"firewall" {
        settings.firewall_enabled = parse_bool(val);
    } else if key == b"block_in" {
        settings.block_inbound = parse_bool(val);
    } else if key == b"log_conn" {
        settings.log_connections = parse_bool(val);
    }
}
