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

//! RFC 1071 16-bit one's-complement Internet checksum. Used both
//! to validate inbound IP headers and to seal outbound ones. The
//! caller is responsible for clearing the checksum field to zero
//! before passing the header buffer in.

pub fn fold(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    if i < bytes.len() {
        sum += u32::from(bytes[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// Convenience: zero the existing checksum field at the given byte
// offset, fold, and return the new value. The header buffer is
// mutated to hold the resulting 16-bit big-endian checksum.
pub fn seal_at(header: &mut [u8], checksum_offset: usize) -> u16 {
    header[checksum_offset] = 0;
    header[checksum_offset + 1] = 0;
    let s = fold(header);
    let be = s.to_be_bytes();
    header[checksum_offset] = be[0];
    header[checksum_offset + 1] = be[1];
    s
}
