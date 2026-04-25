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
use super::address::Ipv6Address;
use super::header::{Ipv6Header, NextHeader};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Ipv6Packet {
    pub header: Ipv6Header,
    pub payload: Vec<u8>,
}

impl Ipv6Packet {
    pub fn new(src: Ipv6Address, dst: Ipv6Address, next: NextHeader, payload: Vec<u8>) -> Self {
        Self {
            header: Ipv6Header {
                version: 6,
                traffic_class: 0,
                flow_label: 0,
                payload_length: payload.len() as u16,
                next_header: next,
                hop_limit: 64,
                src,
                dst,
            },
            payload,
        }
    }

    pub fn src(&self) -> Ipv6Address {
        self.header.src
    }
    pub fn dst(&self) -> Ipv6Address {
        self.header.dst
    }
    pub fn next_header(&self) -> NextHeader {
        self.header.next_header
    }
    pub fn hop_limit(&self) -> u8 {
        self.header.hop_limit
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn decrement_hop_limit(&mut self) -> bool {
        if self.header.hop_limit == 0 {
            return false;
        }
        self.header.hop_limit -= 1;
        self.header.hop_limit > 0
    }
}

pub fn build_ipv6_packet(
    src: Ipv6Address,
    dst: Ipv6Address,
    next: NextHeader,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(40 + payload.len());
    let hdr = Ipv6Header {
        version: 6,
        traffic_class: 0,
        flow_label: 0,
        payload_length: payload.len() as u16,
        next_header: next,
        hop_limit,
        src,
        dst,
    };
    let mut buf = [0u8; 40];
    hdr.serialize(&mut buf);
    pkt.extend_from_slice(&buf);
    pkt.extend_from_slice(payload);
    pkt
}

pub fn parse_ipv6_packet(data: &[u8]) -> Option<Ipv6Packet> {
    let header = Ipv6Header::parse(data)?;
    let payload_start = Ipv6Header::SIZE;
    let payload_end = payload_start + header.payload_length as usize;
    if data.len() < payload_end {
        return None;
    }
    Some(Ipv6Packet { header, payload: data[payload_start..payload_end].to_vec() })
}

pub fn compute_pseudo_header_checksum(
    src: &Ipv6Address,
    dst: &Ipv6Address,
    next_header: u8,
    length: u32,
) -> u32 {
    let mut sum = 0u32;
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src.0[i], src.0[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst.0[i], dst.0[i + 1]]) as u32;
    }
    sum += (length >> 16) as u32;
    sum += (length & 0xffff) as u32;
    sum += next_header as u32;
    sum
}

pub fn finish_checksum(mut sum: u32, data: &[u8]) -> u16 {
    for i in (0..data.len()).step_by(2) {
        let b1 = data[i];
        let b2 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        sum += u16::from_be_bytes([b1, b2]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
