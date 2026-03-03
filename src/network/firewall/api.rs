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

use super::engine::Firewall;
use super::types::{Action, Direction, IpMatch, PortMatch, Protocol, Rule, RuleStats};

static FIREWALL: Firewall = Firewall::new();

pub fn init() -> Result<(), &'static str> {
    FIREWALL.add_rule(Rule {
        id: 0,
        name: String::from("allow-loopback"),
        enabled: true,
        priority: 1000,
        action: Action::Allow,
        direction: Direction::Both,
        protocol: Protocol::Any,
        src_ip: IpMatch::Single([127, 0, 0, 1]),
        dst_ip: IpMatch::Single([127, 0, 0, 1]),
        src_port: PortMatch::Any,
        dst_port: PortMatch::Any,
        rate_limit: None,
        log: false,
        stats: RuleStats::default(),
    });

    FIREWALL.add_rule(Rule {
        id: 0,
        name: String::from("allow-established"),
        enabled: true,
        priority: 999,
        action: Action::Allow,
        direction: Direction::Inbound,
        protocol: Protocol::Any,
        src_ip: IpMatch::Any,
        dst_ip: IpMatch::Any,
        src_port: PortMatch::Any,
        dst_port: PortMatch::Any,
        rate_limit: None,
        log: false,
        stats: RuleStats::default(),
    });

    FIREWALL.add_rule(Rule {
        id: 0,
        name: String::from("allow-dns-out"),
        enabled: true,
        priority: 100,
        action: Action::Allow,
        direction: Direction::Outbound,
        protocol: Protocol::Udp,
        src_ip: IpMatch::Any,
        dst_ip: IpMatch::Any,
        src_port: PortMatch::Any,
        dst_port: PortMatch::Single(53),
        rate_limit: None,
        log: false,
        stats: RuleStats::default(),
    });

    FIREWALL.add_rule(Rule {
        id: 0,
        name: String::from("allow-http-out"),
        enabled: true,
        priority: 100,
        action: Action::Allow,
        direction: Direction::Outbound,
        protocol: Protocol::Tcp,
        src_ip: IpMatch::Any,
        dst_ip: IpMatch::Any,
        src_port: PortMatch::Any,
        dst_port: PortMatch::Range(80, 443),
        rate_limit: None,
        log: false,
        stats: RuleStats::default(),
    });

    FIREWALL.add_rule(Rule {
        id: 0,
        name: String::from("allow-anyone-out"),
        enabled: true,
        priority: 100,
        action: Action::Allow,
        direction: Direction::Outbound,
        protocol: Protocol::Tcp,
        src_ip: IpMatch::Any,
        dst_ip: IpMatch::Any,
        src_port: PortMatch::Any,
        dst_port: PortMatch::Range(9001, 9050),
        rate_limit: None,
        log: false,
        stats: RuleStats::default(),
    });

    crate::log::info!("Firewall initialized with default rules");
    Ok(())
}

pub fn get_firewall() -> &'static Firewall {
    &FIREWALL
}

pub fn filter_inbound(
    protocol: Protocol,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    packet_len: usize,
) -> bool {
    let action = FIREWALL.process_packet(
        Direction::Inbound,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        packet_len,
    );
    action == Action::Allow
}

pub fn filter_outbound(
    protocol: Protocol,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    packet_len: usize,
) -> bool {
    let action = FIREWALL.process_packet(
        Direction::Outbound,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        packet_len,
    );
    action == Action::Allow
}

pub fn add_rule(rule: Rule) -> u32 {
    FIREWALL.add_rule(rule)
}

pub fn remove_rule(id: u32) -> Result<(), &'static str> {
    FIREWALL.remove_rule(id)
}

pub fn maintenance() {
    FIREWALL.cleanup_expired_connections();
}
