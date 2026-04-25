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
use super::duid::Duid;
use crate::network::ipv6::Ipv6Address;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Dhcpv6OptionType {
    ClientId = 1,
    ServerId = 2,
    IaNa = 3,
    IaTa = 4,
    IaAddr = 5,
    OroReq = 6,
    Preference = 7,
    ElapsedTime = 8,
    RelayMsg = 9,
    Auth = 11,
    UnicastSrv = 12,
    StatusCode = 13,
    RapidCommit = 14,
    UserClass = 15,
    VendorClass = 16,
    VendorOpts = 17,
    InterfaceId = 18,
    ReconfMsg = 19,
    ReconfAccept = 20,
    DnsServers = 23,
    DomainList = 24,
    IaPd = 25,
    IaPrefix = 26,
    InfoRefreshTime = 32,
    Fqdn = 39,
    Unknown(u16),
}

impl From<u16> for Dhcpv6OptionType {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::ClientId,
            2 => Self::ServerId,
            3 => Self::IaNa,
            4 => Self::IaTa,
            5 => Self::IaAddr,
            6 => Self::OroReq,
            7 => Self::Preference,
            8 => Self::ElapsedTime,
            9 => Self::RelayMsg,
            11 => Self::Auth,
            12 => Self::UnicastSrv,
            13 => Self::StatusCode,
            14 => Self::RapidCommit,
            15 => Self::UserClass,
            16 => Self::VendorClass,
            17 => Self::VendorOpts,
            18 => Self::InterfaceId,
            19 => Self::ReconfMsg,
            20 => Self::ReconfAccept,
            23 => Self::DnsServers,
            24 => Self::DomainList,
            25 => Self::IaPd,
            26 => Self::IaPrefix,
            32 => Self::InfoRefreshTime,
            39 => Self::Fqdn,
            n => Self::Unknown(n),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Dhcpv6Option {
    ClientId(Duid),
    ServerId(Duid),
    IaNa { iaid: u32, t1: u32, t2: u32, options: Vec<Dhcpv6Option> },
    IaAddr { addr: Ipv6Address, preferred: u32, valid: u32 },
    OroReq(Vec<u16>),
    Preference(u8),
    ElapsedTime(u16),
    StatusCode { code: u16, message: Vec<u8> },
    RapidCommit,
    DnsServers(Vec<Ipv6Address>),
    IaPd { iaid: u32, t1: u32, t2: u32, options: Vec<Dhcpv6Option> },
    IaPrefix { preferred: u32, valid: u32, prefix_len: u8, prefix: Ipv6Address },
    Unknown { code: u16, data: Vec<u8> },
}

pub fn parse_options(data: &[u8]) -> Vec<Dhcpv6Option> {
    let mut opts = Vec::new();
    let mut off = 0;
    while off + 4 <= data.len() {
        let code = u16::from_be_bytes([data[off], data[off + 1]]);
        let len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        if off + 4 + len > data.len() {
            break;
        }
        let opt_data = &data[off + 4..off + 4 + len];
        let opt = match Dhcpv6OptionType::from(code) {
            Dhcpv6OptionType::ClientId => Duid::parse(opt_data).map(Dhcpv6Option::ClientId),
            Dhcpv6OptionType::ServerId => Duid::parse(opt_data).map(Dhcpv6Option::ServerId),
            Dhcpv6OptionType::Preference if len >= 1 => Some(Dhcpv6Option::Preference(opt_data[0])),
            Dhcpv6OptionType::ElapsedTime if len >= 2 => {
                Some(Dhcpv6Option::ElapsedTime(u16::from_be_bytes([opt_data[0], opt_data[1]])))
            }
            Dhcpv6OptionType::RapidCommit => Some(Dhcpv6Option::RapidCommit),
            Dhcpv6OptionType::DnsServers => {
                let addrs: Vec<_> = opt_data
                    .chunks_exact(16)
                    .map(|c| {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(c);
                        Ipv6Address(a)
                    })
                    .collect();
                Some(Dhcpv6Option::DnsServers(addrs))
            }
            Dhcpv6OptionType::StatusCode if len >= 2 => Some(Dhcpv6Option::StatusCode {
                code: u16::from_be_bytes([opt_data[0], opt_data[1]]),
                message: opt_data[2..].to_vec(),
            }),
            _ => Some(Dhcpv6Option::Unknown { code, data: opt_data.to_vec() }),
        };
        if let Some(o) = opt {
            opts.push(o);
        }
        off += 4 + len;
    }
    opts
}

pub fn build_options(opts: &[Dhcpv6Option]) -> Vec<u8> {
    let mut out = Vec::new();
    for opt in opts {
        let (code, data) = match opt {
            Dhcpv6Option::ClientId(d) => (1u16, d.serialize()),
            Dhcpv6Option::ElapsedTime(t) => (8, t.to_be_bytes().to_vec()),
            Dhcpv6Option::OroReq(codes) => {
                (6, codes.iter().flat_map(|c| c.to_be_bytes()).collect())
            }
            Dhcpv6Option::RapidCommit => (14, Vec::new()),
            _ => continue,
        };
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
    }
    out
}
