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
use super::options::{build_options, parse_options, Dhcpv6Option};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcpv6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForward = 12,
    RelayReply = 13,
    Unknown(u8),
}

impl From<u8> for Dhcpv6MessageType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Solicit,
            2 => Self::Advertise,
            3 => Self::Request,
            4 => Self::Confirm,
            5 => Self::Renew,
            6 => Self::Rebind,
            7 => Self::Reply,
            8 => Self::Release,
            9 => Self::Decline,
            10 => Self::Reconfigure,
            11 => Self::InformationRequest,
            12 => Self::RelayForward,
            13 => Self::RelayReply,
            n => Self::Unknown(n),
        }
    }
}

impl Dhcpv6MessageType {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Solicit => 1,
            Self::Advertise => 2,
            Self::Request => 3,
            Self::Confirm => 4,
            Self::Renew => 5,
            Self::Rebind => 6,
            Self::Reply => 7,
            Self::Release => 8,
            Self::Decline => 9,
            Self::Reconfigure => 10,
            Self::InformationRequest => 11,
            Self::RelayForward => 12,
            Self::RelayReply => 13,
            Self::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Dhcpv6Message {
    pub msg_type: Dhcpv6MessageType,
    pub transaction_id: u32,
    pub options: Vec<Dhcpv6Option>,
}

impl Dhcpv6Message {
    pub fn new(msg_type: Dhcpv6MessageType, xid: u32) -> Self {
        Self { msg_type, transaction_id: xid, options: Vec::new() }
    }

    pub fn add_option(&mut self, opt: Dhcpv6Option) {
        self.options.push(opt);
    }

    pub fn get_option<F, T>(&self, f: F) -> Option<T>
    where
        F: Fn(&Dhcpv6Option) -> Option<T>,
    {
        self.options.iter().find_map(f)
    }

    pub fn client_id(&self) -> Option<&super::duid::Duid> {
        self.options.iter().find_map(|o| match o {
            Dhcpv6Option::ClientId(d) => Some(d),
            _ => None,
        })
    }

    pub fn server_id(&self) -> Option<&super::duid::Duid> {
        self.options.iter().find_map(|o| match o {
            Dhcpv6Option::ServerId(d) => Some(d),
            _ => None,
        })
    }
}

pub fn parse_dhcpv6(data: &[u8]) -> Option<Dhcpv6Message> {
    if data.len() < 4 {
        return None;
    }
    let msg_type = Dhcpv6MessageType::from(data[0]);
    let xid = ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | data[3] as u32;
    let options = parse_options(&data[4..]);
    Some(Dhcpv6Message { msg_type, transaction_id: xid, options })
}

pub fn build_dhcpv6(msg: &Dhcpv6Message) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(256);
    pkt.push(msg.msg_type.to_u8());
    pkt.push((msg.transaction_id >> 16) as u8);
    pkt.push((msg.transaction_id >> 8) as u8);
    pkt.push(msg.transaction_id as u8);
    pkt.extend_from_slice(&build_options(&msg.options));
    pkt
}

pub fn generate_transaction_id() -> u32 {
    let mut buf = [0u8; 4];
    crate::security::crypto::random::fill_random_bytes(&mut buf);
    u32::from_be_bytes(buf) & 0x00ff_ffff
}
