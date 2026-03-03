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


pub const IP_PROTOCOL_TCP: u8 = 6;

pub const IP_PROTOCOL_UDP: u8 = 17;

pub const IP_PROTOCOL_ICMP: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddress {
    pub fn v4(a: u8, b: u8, c: u8, d: u8) -> Self {
        IpAddress::V4([a, b, c, d])
    }

    pub fn is_unspecified(&self) -> bool {
        match self {
            IpAddress::V4(addr) => *addr == [0, 0, 0, 0],
            IpAddress::V6(addr) => *addr == [0; 16],
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self {
            IpAddress::V4(addr) => addr[0] == 127,
            IpAddress::V6(addr) => *addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }
    }

    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpAddress::V4(_))
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpAddress::V6(_))
    }
}
