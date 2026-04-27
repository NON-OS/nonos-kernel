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
use crate::network::firewall::types::{Direction, IpMatch, PortMatch, Protocol};

impl Firewall {
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
                let mask =
                    if *prefix >= 32 { 0xFFFFFFFF_u32 } else { !((1u32 << (32 - prefix)) - 1) };
                let ip_val = u32::from_be_bytes(ip);
                let addr_val = u32::from_be_bytes(*addr);
                (ip_val & mask) == (addr_val & mask)
            }
            IpMatch::Range(start, end) => {
                let ip_val = u32::from_be_bytes(ip);
                ip_val >= u32::from_be_bytes(*start) && ip_val <= u32::from_be_bytes(*end)
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
