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

pub const ETH_HDR: usize = 14;
pub const ET_IPV4: u16 = 0x0800;
pub const ET_ARP: u16 = 0x0806;
pub const IP_PROTO_UDP: u8 = 17;

#[repr(C, packed)]
pub(super) struct EthHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub et_be: [u8; 2],
}

#[repr(C, packed)]
pub struct Ipv4Header {
    pub vihl: u8,
    pub dscp_ecn: u8,
    pub total_len_be: [u8; 2],
    pub id_be: [u8; 2],
    pub flags_frag_be: [u8; 2],
    pub ttl: u8,
    pub proto: u8,
    pub hdr_checksum_be: [u8; 2],
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

#[repr(C, packed)]
pub struct UdpHeader {
    pub sport_be: [u8; 2],
    pub dport_be: [u8; 2],
    pub len_be: [u8; 2],
    pub csum_be: [u8; 2],
}

#[inline]
pub fn be16(b: [u8; 2]) -> u16 {
    u16::from_be_bytes(b)
}

#[inline]
pub fn to_be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

#[inline]
pub fn to_be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

pub fn ipv4_from_u32(ip: u32) -> [u8; 4] {
    to_be32(ip)
}

pub fn ipv4_from_octets(a: u8, b: u8, c: u8, d: u8) -> [u8; 4] {
    [a, b, c, d]
}

pub(super) fn csum16(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn ip_checksum(h: &Ipv4Header) -> u16 {
    // SAFETY: Ipv4Header is repr(C, packed) and exactly 20 bytes
    let w = unsafe { core::slice::from_raw_parts(h as *const _ as *const u16, 10) };
    let mut sum = 0u32;
    for (i, v) in w.iter().enumerate() {
        if i == 5 {
            continue;
        }
        sum += u16::from_be(*v) as u32;
    }
    csum16(sum)
}

pub(super) fn udp_checksum(ip: &Ipv4Header, udp: &UdpHeader, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += u16::from_be_bytes([ip.src[0], ip.src[1]]) as u32;
    sum += u16::from_be_bytes([ip.src[2], ip.src[3]]) as u32;
    sum += u16::from_be_bytes([ip.dst[0], ip.dst[1]]) as u32;
    sum += u16::from_be_bytes([ip.dst[2], ip.dst[3]]) as u32;
    sum += IP_PROTO_UDP as u32;
    let udp_len = u16::from_be_bytes(udp.len_be) as u32;
    sum += udp_len;
    // SAFETY: UdpHeader is repr(C, packed) and exactly 8 bytes
    let uw = unsafe { core::slice::from_raw_parts(udp as *const _ as *const u16, 4) };
    for v in uw {
        sum += u16::from_be(*v) as u32;
    }
    let mut i = 0;
    while i + 1 < payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += u16::from_be_bytes([payload[i], 0]) as u32;
    }
    csum16(sum)
}
