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

use super::address::Ipv6Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NextHeader {
    HopByHop = 0,
    Tcp = 6,
    Udp = 17,
    Ipv6Route = 43,
    Ipv6Frag = 44,
    Icmpv6 = 58,
    Ipv6NoNxt = 59,
    Ipv6Opts = 60,
    Unknown(u8),
}

impl From<u8> for NextHeader {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::HopByHop,
            6 => Self::Tcp,
            17 => Self::Udp,
            43 => Self::Ipv6Route,
            44 => Self::Ipv6Frag,
            58 => Self::Icmpv6,
            59 => Self::Ipv6NoNxt,
            60 => Self::Ipv6Opts,
            n => Self::Unknown(n),
        }
    }
}

impl From<NextHeader> for u8 {
    fn from(h: NextHeader) -> u8 {
        match h {
            NextHeader::HopByHop => 0,
            NextHeader::Tcp => 6,
            NextHeader::Udp => 17,
            NextHeader::Ipv6Route => 43,
            NextHeader::Ipv6Frag => 44,
            NextHeader::Icmpv6 => 58,
            NextHeader::Ipv6NoNxt => 59,
            NextHeader::Ipv6Opts => 60,
            NextHeader::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: NextHeader,
    pub hop_limit: u8,
    pub src: Ipv6Address,
    pub dst: Ipv6Address,
}

impl Ipv6Header {
    pub const SIZE: usize = 40;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }
        let ver = data[0] >> 4;
        if ver != 6 {
            return None;
        }
        let tc = ((data[0] & 0x0f) << 4) | (data[1] >> 4);
        let fl = ((data[1] as u32 & 0x0f) << 16) | ((data[2] as u32) << 8) | data[3] as u32;
        let pl = u16::from_be_bytes([data[4], data[5]]);
        let nh = NextHeader::from(data[6]);
        let hl = data[7];
        let mut src = [0u8; 16];
        src.copy_from_slice(&data[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&data[24..40]);
        Some(Self {
            version: 6,
            traffic_class: tc,
            flow_label: fl,
            payload_length: pl,
            next_header: nh,
            hop_limit: hl,
            src: Ipv6Address(src),
            dst: Ipv6Address(dst),
        })
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        if buf.len() < 40 {
            return None;
        }
        buf[0] = (6 << 4) | (self.traffic_class >> 4);
        buf[1] = ((self.traffic_class & 0x0f) << 4) | ((self.flow_label >> 16) as u8 & 0x0f);
        buf[2] = (self.flow_label >> 8) as u8;
        buf[3] = self.flow_label as u8;
        buf[4..6].copy_from_slice(&self.payload_length.to_be_bytes());
        buf[6] = u8::from(self.next_header);
        buf[7] = self.hop_limit;
        buf[8..24].copy_from_slice(&self.src.0);
        buf[24..40].copy_from_slice(&self.dst.0);
        Some(40)
    }
}

#[derive(Debug, Clone)]
pub struct Ipv6ExtHeader {
    pub next_header: NextHeader,
    pub length: u8,
    pub data: [u8; 254],
}

impl Ipv6ExtHeader {
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }
        let nh = NextHeader::from(data[0]);
        let len = ((data[1] as usize) + 1) * 8;
        if data.len() < len {
            return None;
        }
        let mut ext = Self { next_header: nh, length: data[1], data: [0; 254] };
        let copy_len = (len - 2).min(254);
        ext.data[..copy_len].copy_from_slice(&data[2..2 + copy_len]);
        Some((ext, len))
    }
}
