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

use super::addr::Ipv4Addr;

pub const HDR_LEN_MIN: usize = 20;
pub const HDR_LEN_MAX: usize = 60;
pub const VERSION_4: u8 = 4;
pub const DEFAULT_TTL: u8 = 64;

pub const CHECKSUM_OFFSET: usize = 10;
pub const TOTAL_LEN_OFFSET: usize = 2;
pub const TTL_OFFSET: usize = 8;
pub const PROTO_OFFSET: usize = 9;
pub const SRC_OFFSET: usize = 12;
pub const DST_OFFSET: usize = 16;

pub const FLAG_DONT_FRAGMENT: u16 = 0x4000;
pub const FLAG_MORE_FRAGMENTS: u16 = 0x2000;
pub const FRAGMENT_OFFSET_MASK: u16 = 0x1FFF;

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Header {
    pub ihl_words: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4Header {
    pub fn header_bytes(&self) -> usize {
        (self.ihl_words as usize) * 4
    }

    pub fn payload_bytes(&self) -> usize {
        (self.total_length as usize).saturating_sub(self.header_bytes())
    }

    pub fn is_fragment(&self) -> bool {
        self.flags_fragment & (FRAGMENT_OFFSET_MASK | FLAG_MORE_FRAGMENTS) != 0
    }
}
