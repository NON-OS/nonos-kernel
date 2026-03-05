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

//! Ethernet type constants and enumerations

/// IPv4 EtherType
pub const ETHERTYPE_IP: u16 = 0x0800;

/// IPv6 EtherType
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// ARP EtherType
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// Ethernet frame type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
}

impl EtherType {
    /// Convert from raw u16 ethertype value
    pub fn from_u16(val: u16) -> Self {
        match val {
            ETHERTYPE_IP => EtherType::Ipv4,
            ETHERTYPE_IPV6 => EtherType::Ipv6,
            ETHERTYPE_ARP => EtherType::Arp,
            x => EtherType::Other(x),
        }
    }

    /// Convert to raw u16 ethertype value
    pub fn to_u16(self) -> u16 {
        match self {
            EtherType::Ipv4 => ETHERTYPE_IP,
            EtherType::Ipv6 => ETHERTYPE_IPV6,
            EtherType::Arp => ETHERTYPE_ARP,
            EtherType::Other(x) => x,
        }
    }
}
