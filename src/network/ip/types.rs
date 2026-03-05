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

//! IP address types and protocol constants

/// IP protocol number for TCP
pub const IP_PROTOCOL_TCP: u8 = 6;

/// IP protocol number for UDP
pub const IP_PROTOCOL_UDP: u8 = 17;

/// IP protocol number for ICMP
pub const IP_PROTOCOL_ICMP: u8 = 1;

/// IP address (v4 or v6)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddress {
    /// Create IPv4 address from bytes
    pub fn v4(a: u8, b: u8, c: u8, d: u8) -> Self {
        IpAddress::V4([a, b, c, d])
    }

    /// Check if address is unspecified (0.0.0.0 or ::)
    pub fn is_unspecified(&self) -> bool {
        match self {
            IpAddress::V4(addr) => *addr == [0, 0, 0, 0],
            IpAddress::V6(addr) => *addr == [0; 16],
        }
    }

    /// Check if address is loopback
    pub fn is_loopback(&self) -> bool {
        match self {
            IpAddress::V4(addr) => addr[0] == 127,
            IpAddress::V6(addr) => *addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }
    }

    /// Check if address is IPv4
    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpAddress::V4(_))
    }

    /// Check if address is IPv6
    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpAddress::V6(_))
    }
}
