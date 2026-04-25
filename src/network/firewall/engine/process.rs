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

use super::firewall::Firewall;
use crate::network::firewall::types::{Action, ConnState, ConnTrack, Direction, Protocol};
use core::sync::atomic::Ordering;

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
        if direction == Direction::Inbound {
            if !super::blacklist::check_ip(src_ip) {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                return Action::Drop;
            }
            if super::synflood::is_blocked(src_ip) || super::portscan::is_scanner_blocked(src_ip) {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                return Action::Drop;
            }
            if protocol == Protocol::Tcp
                && !super::portscan::track_connection_attempt(src_ip, dst_port)
            {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                return Action::Drop;
            }
        }
        let conn_key = Self::conn_key(src_ip, dst_ip, src_port, dst_port, protocol);
        let reverse_key = Self::conn_key(dst_ip, src_ip, dst_port, src_port, protocol);
        if let Some(action) = self.check_conntrack(conn_key, reverse_key, direction, packet_len) {
            return action;
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
            rule.stats.bytes.fetch_add(packet_len as u64, Ordering::Relaxed);
            rule.stats.last_match_ms.store(crate::time::timestamp_millis(), Ordering::Relaxed);
            if rule.log {
                self.log_packet(
                    &rule.action,
                    protocol,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    &rule.name,
                );
            }
            if rule.action == Action::Allow && direction == Direction::Outbound {
                self.create_conntrack(
                    conn_key, src_ip, dst_ip, src_port, dst_port, protocol, packet_len,
                );
            }
            if rule.action == Action::Log {
                continue;
            }
            self.update_action_stats(rule.action);
            return rule.action;
        }
        let action = match direction {
            Direction::Inbound => self.default_inbound,
            Direction::Outbound => self.default_outbound,
            Direction::Both => self.default_inbound,
        };
        self.update_action_stats(action);
        action
    }

    fn check_conntrack(
        &self,
        conn_key: u64,
        reverse_key: u64,
        direction: Direction,
        packet_len: usize,
    ) -> Option<Action> {
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
                return Some(Action::Allow);
            }
        } else if let Some(conn) = ct.get_mut(&reverse_key) {
            conn.last_seen_ms = crate::time::timestamp_millis();
            conn.state = ConnState::Established;
            self.stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
            return Some(Action::Allow);
        }
        None
    }

    fn create_conntrack(
        &self,
        key: u64,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        packet_len: usize,
    ) {
        let now = crate::time::timestamp_millis();
        let timeout_ms = match protocol {
            Protocol::Tcp => 300_000,
            Protocol::Udp => 60_000,
            _ => 30_000,
        };
        let mut ct = self.conntrack.lock();
        ct.insert(
            key,
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
                timeout_ms,
            },
        );
        self.stats.connections_tracked.fetch_add(1, Ordering::Relaxed);
    }
}
