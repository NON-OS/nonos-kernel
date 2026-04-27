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
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Address(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    pub address: Ipv6Address,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Scope {
    Global,
    LinkLocal,
    SiteLocal,
    Loopback,
    Multicast,
    Unspecified,
}

impl Ipv6Address {
    pub const UNSPECIFIED: Self = Self([0; 16]);
    pub const LOOPBACK: Self = Self([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pub const ALL_NODES_LINK: Self = Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    pub const ALL_ROUTERS_LINK: Self = Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub fn from_segments(s: [u16; 8]) -> Self {
        let mut b = [0u8; 16];
        for i in 0..8 {
            b[i * 2] = (s[i] >> 8) as u8;
            b[i * 2 + 1] = s[i] as u8;
        }
        Self(b)
    }
    pub fn segments(&self) -> [u16; 8] {
        let mut s = [0u16; 8];
        for i in 0..8 {
            s[i] = ((self.0[i * 2] as u16) << 8) | self.0[i * 2 + 1] as u16;
        }
        s
    }
    pub fn octets(&self) -> [u8; 16] {
        self.0
    }
    pub fn scope(&self) -> Ipv6Scope {
        if self.0 == [0; 16] {
            return Ipv6Scope::Unspecified;
        }
        if self.0 == Self::LOOPBACK.0 {
            return Ipv6Scope::Loopback;
        }
        if self.0[0] == 0xff {
            return Ipv6Scope::Multicast;
        }
        if self.0[0] == 0xfe && (self.0[1] & 0xc0) == 0x80 {
            return Ipv6Scope::LinkLocal;
        }
        if self.0[0] == 0xfe && (self.0[1] & 0xc0) == 0xc0 {
            return Ipv6Scope::SiteLocal;
        }
        Ipv6Scope::Global
    }
    pub fn is_link_local(&self) -> bool {
        matches!(self.scope(), Ipv6Scope::LinkLocal)
    }
    pub fn is_multicast(&self) -> bool {
        self.0[0] == 0xff
    }
    pub fn is_unspecified(&self) -> bool {
        self.0 == [0; 16]
    }
    pub fn is_loopback(&self) -> bool {
        self.0 == Self::LOOPBACK.0
    }
    pub fn solicited_node(&self) -> Self {
        Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, self.0[13], self.0[14], self.0[15]])
    }
}

impl Ipv6Cidr {
    pub fn new(addr: Ipv6Address, prefix: u8) -> Self {
        Self { address: addr, prefix_len: prefix.min(128) }
    }
    pub fn contains(&self, addr: &Ipv6Address) -> bool {
        let full = (self.prefix_len / 8) as usize;
        let rem = self.prefix_len % 8;
        if self.address.0[..full] != addr.0[..full] {
            return false;
        }
        if rem > 0 && full < 16 {
            let mask = 0xffu8 << (8 - rem);
            if (self.address.0[full] & mask) != (addr.0[full] & mask) {
                return false;
            }
        }
        true
    }
}

pub fn parse_ipv6(s: &str) -> Option<Ipv6Address> {
    let parts: Vec<&str> = s.split("::").collect();
    if parts.len() > 2 {
        return None;
    }
    let mut segs = [0u16; 8];
    let left: Vec<&str> =
        if parts[0].is_empty() { Vec::new() } else { parts[0].split(':').collect() };
    let right: Vec<&str> = if parts.len() == 2 && !parts[1].is_empty() {
        parts[1].split(':').collect()
    } else {
        Vec::new()
    };
    if left.len() + right.len() > 8 {
        return None;
    }
    for (i, p) in left.iter().enumerate() {
        segs[i] = u16::from_str_radix(p, 16).ok()?;
    }
    let start = 8 - right.len();
    for (i, p) in right.iter().enumerate() {
        segs[start + i] = u16::from_str_radix(p, 16).ok()?;
    }
    Some(Ipv6Address::from_segments(segs))
}

pub fn format_ipv6(addr: &Ipv6Address) -> String {
    let s = addr.segments();
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]
    )
}
