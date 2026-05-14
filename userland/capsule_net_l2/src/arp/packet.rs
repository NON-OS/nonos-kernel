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

use crate::ethernet::MacAddress;

pub const PACKET_LEN: usize = 28;

pub const HW_ETHERNET: u16 = 1;
pub const PROTO_IPV4: u16 = 0x0800;
pub const HLEN_MAC: u8 = 6;
pub const PLEN_IPV4: u8 = 4;

pub const OPER_REQUEST: u16 = 1;
pub const OPER_REPLY: u16 = 2;

#[derive(Clone, Copy, Debug)]
pub struct ArpPacket {
    pub oper: u16,
    pub sender_mac: MacAddress,
    pub sender_ip: [u8; 4],
    pub target_mac: MacAddress,
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < PACKET_LEN {
            return None;
        }
        if u16::from_be_bytes([bytes[0], bytes[1]]) != HW_ETHERNET {
            return None;
        }
        if u16::from_be_bytes([bytes[2], bytes[3]]) != PROTO_IPV4 {
            return None;
        }
        if bytes[4] != HLEN_MAC || bytes[5] != PLEN_IPV4 {
            return None;
        }
        let oper = u16::from_be_bytes([bytes[6], bytes[7]]);
        let mut sender_mac = [0u8; 6];
        let mut target_mac = [0u8; 6];
        let mut sender_ip = [0u8; 4];
        let mut target_ip = [0u8; 4];
        sender_mac.copy_from_slice(&bytes[8..14]);
        sender_ip.copy_from_slice(&bytes[14..18]);
        target_mac.copy_from_slice(&bytes[18..24]);
        target_ip.copy_from_slice(&bytes[24..28]);
        Some(Self { oper, sender_mac, sender_ip, target_mac, target_ip })
    }

    pub fn write(&self, out: &mut [u8]) {
        debug_assert!(out.len() >= PACKET_LEN);
        out[0..2].copy_from_slice(&HW_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&PROTO_IPV4.to_be_bytes());
        out[4] = HLEN_MAC;
        out[5] = PLEN_IPV4;
        out[6..8].copy_from_slice(&self.oper.to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac);
        out[14..18].copy_from_slice(&self.sender_ip);
        out[18..24].copy_from_slice(&self.target_mac);
        out[24..28].copy_from_slice(&self.target_ip);
    }
}
