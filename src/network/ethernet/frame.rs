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


use super::types::EtherType;

#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    pub const SIZE: usize = 14;

    pub fn new(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Self {
        Self { dst, src, ethertype }
    }

    pub fn to_bytes(&self) -> [u8; 14] {
        let mut bytes = [0u8; 14];
        bytes[0..6].copy_from_slice(&self.dst);
        bytes[6..12].copy_from_slice(&self.src);
        bytes[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct EthernetFrame<'a> {
    pub header: EthernetHeader,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < EthernetHeader::SIZE {
            return Err("ethernet: frame too short");
        }

        let mut dst = [0u8; 6];
        dst.copy_from_slice(&bytes[0..6]);

        let mut src = [0u8; 6];
        src.copy_from_slice(&bytes[6..12]);

        let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);

        Ok(Self {
            header: EthernetHeader { dst, src, ethertype },
            payload: &bytes[14..],
        })
    }

    pub fn ethertype(&self) -> EtherType {
        EtherType::from_u16(self.header.ethertype)
    }

    pub fn is_broadcast(&self) -> bool {
        self.header.dst == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    }

    pub fn is_multicast(&self) -> bool {
        self.header.dst[0] & 0x01 != 0
    }
}
