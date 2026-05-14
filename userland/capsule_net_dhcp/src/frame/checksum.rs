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

//! RFC 1071 ones-complement checksum. The DHCP capsule owns its
//! own copy because it cannot route through `net.ip` for the
//! outbound BOOTP exchange — the source IPv4 is 0.0.0.0 before a
//! lease exists.

pub fn fold(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum = sum.wrapping_add(u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32);
        i += 2;
    }
    if i < bytes.len() {
        sum = sum.wrapping_add((bytes[i] as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn fold_with_pseudo(src: &[u8; 4], dst: &[u8; 4], proto: u8, body: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum = sum.wrapping_add(u16::from_be_bytes([src[0], src[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([src[2], src[3]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst[0], dst[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst[2], dst[3]]) as u32);
    sum = sum.wrapping_add(proto as u32);
    sum = sum.wrapping_add(body.len() as u32);
    let mut i = 0;
    while i + 1 < body.len() {
        sum = sum.wrapping_add(u16::from_be_bytes([body[i], body[i + 1]]) as u32);
        i += 2;
    }
    if i < body.len() {
        sum = sum.wrapping_add((body[i] as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let c = !(sum as u16);
    if c == 0 {
        0xFFFF
    } else {
        c
    }
}
