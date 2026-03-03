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

use core::sync::atomic::Ordering;

use super::engine_core::Firewall;
use super::types::{
    format_ip, Action, ConnState, ConnTrack, Direction, IpMatch, PortMatch, Protocol,
};

impl Firewall {
    pub fn process_packet(
        &self,
        direction: Direction,
        protocol: Protocol,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        packet_len: usize,
    ) -> Action {
        if !self.enabled.load(Ordering::Relaxed) {
            return Action::Allow;
        }

        let conn_key = Self::conn_key(src_ip, dst_ip, src_port, dst_port, protocol);
        let reverse_key = Self::conn_key(dst_ip, src_ip, dst_port, src_port, protocol);

        {
            let mut ct = self.conntrack.lock();
            if let Some(conn) = ct.get_mut(&conn_key) {
                conn.last_seen_ms = crate::time::timestamp_millis();
                match direction {
                    Direction::Inbound => {
                        conn.packets_in += 1;
                        conn.bytes_in += packet_len as u64;
                    }
                    Direction::Outbound => {
                        conn.packets_out += 1;
                        conn.bytes_out += packet_len as u64;
                    }
                    Direction::Both => {}
                }
                if conn.state == ConnState::Established {
                    self.stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
                    return Action::Allow;
                }
            } else if let Some(conn) = ct.get_mut(&reverse_key) {
                conn.last_seen_ms = crate::time::timestamp_millis();
                conn.state = ConnState::Established;
                self.stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
                return Action::Allow;
            }
        }

        let rules = self.rules.read();
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            if !Self::direction_matches(direction, rule.direction) {
                continue;
            }

            if !Self::protocol_matches(protocol, rule.protocol) {
                continue;
            }

            if !Self::ip_matches(src_ip, &rule.src_ip) {
                continue;
            }

            if !Self::ip_matches(dst_ip, &rule.dst_ip) {
                continue;
            }

            if !Self::port_matches(src_port, &rule.src_port) {
                continue;
            }

            if !Self::port_matches(dst_port, &rule.dst_port) {
                continue;
            }

            rule.stats.matches.fetch_add(1, Ordering::Relaxed);
            rule.stats
                .bytes
                .fetch_add(packet_len as u64, Ordering::Relaxed);
            rule.stats
                .last_match_ms
                .store(crate::time::timestamp_millis(), Ordering::Relaxed);

            if rule.log {
                self.stats.packets_logged.fetch_add(1, Ordering::Relaxed);
                crate::log::info!(
                    "FW: {} {:?} {}:{} -> {}:{} rule={}",
                    match rule.action {
                        Action::Allow => "ALLOW",
                        Action::Deny => "DENY",
                        Action::Drop => "DROP",
                        Action::Log => "LOG",
                        Action::RateLimit => "RATELIMIT",
                    },
                    protocol,
                    format_ip(src_ip),
                    src_port,
                    format_ip(dst_ip),
                    dst_port,
                    rule.name
                );
            }

            if rule.action == Action::Allow && direction == Direction::Outbound {
                let mut ct = self.conntrack.lock();
                let now = crate::time::timestamp_millis();
                ct.insert(
                    conn_key,
                    ConnTrack {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        protocol,
                        state: ConnState::New,
                        packets_in: 0,
                        packets_out: 1,
                        bytes_in: 0,
                        bytes_out: packet_len as u64,
                        created_ms: now,
                        last_seen_ms: now,
                        timeout_ms: match protocol {
                            Protocol::Tcp => 300_000,
                            Protocol::Udp => 60_000,
                            _ => 30_000,
                        },
                    },
                );
                self.stats
                    .connections_tracked
                    .fetch_add(1, Ordering::Relaxed);
            }

            match rule.action {
                Action::Allow => {
                    self.stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
                }
                Action::Deny => {
                    self.stats.packets_denied.fetch_add(1, Ordering::Relaxed);
                }
                Action::Drop => {
                    self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                }
                Action::RateLimit => {
                    self.stats
                        .packets_rate_limited
                        .fetch_add(1, Ordering::Relaxed);
                }
                Action::Log => {
                    continue;
                }
            }

            return rule.action;
        }

        let action = match direction {
            Direction::Inbound => self.default_inbound,
            Direction::Outbound => self.default_outbound,
            Direction::Both => self.default_inbound,
        };

        match action {
            Action::Allow => self.stats.packets_allowed.fetch_add(1, Ordering::Relaxed),
            Action::Deny => self.stats.packets_denied.fetch_add(1, Ordering::Relaxed),
            Action::Drop => self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };

        action
    }

    pub(super) fn conn_key(
        src_ip: [u8; 4],
        _dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        proto: Protocol,
    ) -> u64 {
        let mut key: u64 = 0;
        key |= (src_ip[0] as u64) << 56;
        key |= (src_ip[1] as u64) << 48;
        key |= (src_ip[2] as u64) << 40;
        key |= (src_ip[3] as u64) << 32;
        key |= (src_port as u64) << 16;
        key |= dst_port as u64;
        key ^= (proto as u64) << 60;
        key
    }

    pub(super) fn direction_matches(actual: Direction, rule: Direction) -> bool {
        match rule {
            Direction::Both => true,
            _ => actual == rule,
        }
    }

    pub(super) fn protocol_matches(actual: Protocol, rule: Protocol) -> bool {
        match rule {
            Protocol::Any => true,
            _ => actual == rule,
        }
    }

    pub(super) fn ip_matches(ip: [u8; 4], rule: &IpMatch) -> bool {
        match rule {
            IpMatch::Any => true,
            IpMatch::Single(addr) => ip == *addr,
            IpMatch::Subnet(addr, prefix) => {
                let mask = if *prefix >= 32 {
                    0xFFFFFFFF_u32
                } else {
                    !((1u32 << (32 - prefix)) - 1)
                };
                let ip_val = u32::from_be_bytes(ip);
                let addr_val = u32::from_be_bytes(*addr);
                (ip_val & mask) == (addr_val & mask)
            }
            IpMatch::Range(start, end) => {
                let ip_val = u32::from_be_bytes(ip);
                let start_val = u32::from_be_bytes(*start);
                let end_val = u32::from_be_bytes(*end);
                ip_val >= start_val && ip_val <= end_val
            }
        }
    }

    pub(super) fn port_matches(port: u16, rule: &PortMatch) -> bool {
        match rule {
            PortMatch::Any => true,
            PortMatch::Single(p) => port == *p,
            PortMatch::Range(start, end) => port >= *start && port <= *end,
            PortMatch::List(ports, len) => ports[..*len].contains(&port),
        }
    }
}
