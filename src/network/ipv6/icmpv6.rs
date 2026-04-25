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
use super::packet::{compute_pseudo_header_checksum, finish_checksum};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Icmpv6Type {
    DestUnreach = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParamProblem = 4,
    EchoRequest = 128,
    EchoReply = 129,
    RouterSol = 133,
    RouterAdv = 134,
    NeighborSol = 135,
    NeighborAdv = 136,
    Redirect = 137,
    Unknown(u8),
}

impl From<u8> for Icmpv6Type {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::DestUnreach,
            2 => Self::PacketTooBig,
            3 => Self::TimeExceeded,
            4 => Self::ParamProblem,
            128 => Self::EchoRequest,
            129 => Self::EchoReply,
            133 => Self::RouterSol,
            134 => Self::RouterAdv,
            135 => Self::NeighborSol,
            136 => Self::NeighborAdv,
            137 => Self::Redirect,
            n => Self::Unknown(n),
        }
    }
}

impl Icmpv6Type {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::DestUnreach => 1,
            Self::PacketTooBig => 2,
            Self::TimeExceeded => 3,
            Self::ParamProblem => 4,
            Self::EchoRequest => 128,
            Self::EchoReply => 129,
            Self::RouterSol => 133,
            Self::RouterAdv => 134,
            Self::NeighborSol => 135,
            Self::NeighborAdv => 136,
            Self::Redirect => 137,
            Self::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Icmpv6Message {
    pub msg_type: Icmpv6Type,
    pub code: u8,
    pub checksum: u16,
    pub body: Vec<u8>,
}

impl Icmpv6Message {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        Some(Self {
            msg_type: Icmpv6Type::from(data[0]),
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            body: data[4..].to_vec(),
        })
    }

    pub fn serialize(&self, src: &Ipv6Address, dst: &Ipv6Address) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(4 + self.body.len());
        pkt.push(self.msg_type.to_u8());
        pkt.push(self.code);
        pkt.push(0);
        pkt.push(0);
        pkt.extend_from_slice(&self.body);
        let sum = compute_pseudo_header_checksum(src, dst, 58, pkt.len() as u32);
        let cs = finish_checksum(sum, &pkt);
        pkt[2] = (cs >> 8) as u8;
        pkt[3] = cs as u8;
        pkt
    }
}

pub fn build_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + payload.len());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(&seq.to_be_bytes());
    body.extend_from_slice(payload);
    body
}

pub fn build_neighbor_solicitation(target: &Ipv6Address, src_mac: &[u8; 6]) -> Vec<u8> {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&target.0);
    body.push(1);
    body.push(1);
    body.extend_from_slice(src_mac);
    body
}

pub fn build_neighbor_advertisement(target: &Ipv6Address, src_mac: &[u8; 6], flags: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(24);
    body.push(flags);
    body.extend_from_slice(&[0; 3]);
    body.extend_from_slice(&target.0);
    body.push(2);
    body.push(1);
    body.extend_from_slice(src_mac);
    body
}

pub fn send_icmpv6(src: &Ipv6Address, dst: &Ipv6Address, msg: &Icmpv6Message) -> Result<(), i32> {
    let payload = msg.serialize(src, dst);
    let pkt = super::packet::build_ipv6_packet(
        *src,
        *dst,
        super::header::NextHeader::Icmpv6,
        64,
        &payload,
    );
    crate::network::stack::send_ipv6_packet(&pkt)
}

pub fn handle_icmpv6(src: &Ipv6Address, _dst: &Ipv6Address, data: &[u8]) -> Option<Icmpv6Message> {
    let msg = Icmpv6Message::parse(data)?;
    match msg.msg_type {
        Icmpv6Type::NeighborAdv if msg.body.len() >= 20 => {
            let mut target = [0u8; 16];
            target.copy_from_slice(&msg.body[4..20]);
            if msg.body.len() >= 28 && msg.body[20] == 2 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&msg.body[22..28]);
                super::neighbor::update_neighbor(
                    &Ipv6Address(target),
                    mac,
                    (msg.body[0] & 0x80) != 0,
                );
            }
        }
        Icmpv6Type::RouterAdv => {
            super::slaac::process_ra(src, &msg.body);
        }
        _ => {}
    }
    Some(msg)
}
