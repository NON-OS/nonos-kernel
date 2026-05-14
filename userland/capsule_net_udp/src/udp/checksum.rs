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

//! IPv4 UDP checksum. RFC 768 + 1071: fold over the IPv4 pseudo-
//! header (src, dst, zero, protocol=17, udp_length) followed by
//! the UDP header and payload. The pseudo-header bytes are
//! constructed on the stack to keep the buffer caller-local.

const IPPROTO_UDP: u8 = 17;

fn add(sum: &mut u32, word: u16) {
    *sum = sum.wrapping_add(u32::from(word));
}

fn add_bytes(sum: &mut u32, bytes: &[u8]) {
    let mut i = 0;
    while i + 1 < bytes.len() {
        add(sum, u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    if i < bytes.len() {
        add(sum, u16::from_be_bytes([bytes[i], 0]));
    }
}

pub fn compute(src: &[u8; 4], dst: &[u8; 4], udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    add_bytes(&mut sum, src);
    add_bytes(&mut sum, dst);
    add(&mut sum, u16::from(IPPROTO_UDP));
    add(&mut sum, udp_segment.len() as u16);
    add_bytes(&mut sum, udp_segment);
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
