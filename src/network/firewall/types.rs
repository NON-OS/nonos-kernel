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

//! Firewall type definitions.

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

/// Firewall action for a rule
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
    Drop,
    Log,
    RateLimit,
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

/// Traffic direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

/// IP address match specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMatch {
    Any,
    Single([u8; 4]),
    Subnet([u8; 4], u8),
    Range([u8; 4], [u8; 4]),
}

/// Port match specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMatch {
    Any,
    Single(u16),
    Range(u16, u16),
    List([u16; 8], usize),
}

/// Rate limiting configuration
#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    pub packets_per_second: u32,
    pub burst_size: u32,
}

/// Statistics for a rule
#[derive(Debug, Default)]
pub struct RuleStats {
    pub matches: AtomicU64,
    pub bytes: AtomicU64,
    pub last_match_ms: AtomicU64,
}

impl Clone for RuleStats {
    fn clone(&self) -> Self {
        Self {
            matches: AtomicU64::new(self.matches.load(Ordering::Relaxed)),
            bytes: AtomicU64::new(self.bytes.load(Ordering::Relaxed)),
            last_match_ms: AtomicU64::new(self.last_match_ms.load(Ordering::Relaxed)),
        }
    }
}

/// Firewall rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    pub priority: u32,
    pub action: Action,
    pub direction: Direction,
    pub protocol: Protocol,
    pub src_ip: IpMatch,
    pub dst_ip: IpMatch,
    pub src_port: PortMatch,
    pub dst_port: PortMatch,
    pub rate_limit: Option<RateLimit>,
    pub log: bool,
    pub stats: RuleStats,
}

/// Connection state for stateful firewall
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    New,
    Established,
    Related,
    Invalid,
    TimeWait,
}

/// Connection tracking entry
#[derive(Debug, Clone)]
pub struct ConnTrack {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub state: ConnState,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub created_ms: u64,
    pub last_seen_ms: u64,
    pub timeout_ms: u64,
}

/// Firewall statistics
#[derive(Debug, Default)]
pub struct FirewallStats {
    pub packets_allowed: AtomicU64,
    pub packets_denied: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub packets_logged: AtomicU64,
    pub packets_rate_limited: AtomicU64,
    pub connections_tracked: AtomicU64,
    pub connections_expired: AtomicU64,
}

/// Format IP address for logging
pub fn format_ip(ip: [u8; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
