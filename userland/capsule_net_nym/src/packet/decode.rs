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

use crate::crypto::Nonce;

use super::header::{WIRE_MAGIC, WIRE_VERSION};
use super::types::{Decoded, PacketError, HEADER_LEN};

pub fn decode(packet: &[u8]) -> Result<Decoded<'_>, PacketError> {
    if packet.len() < HEADER_LEN {
        return Err(PacketError::Short);
    }
    if le32(packet, 0) != WIRE_MAGIC {
        return Err(PacketError::BadMagic);
    }
    if packet[4] != WIRE_VERSION {
        return Err(PacketError::BadVersion);
    }
    let len = u16::from_le_bytes([packet[6], packet[7]]) as usize;
    if HEADER_LEN + len > packet.len() {
        return Err(PacketError::BadLength);
    }
    Ok(Decoded {
        session_id: le32(packet, 8),
        flags: packet[5],
        nonce: nonce(packet),
        ciphertext: &packet[HEADER_LEN..HEADER_LEN + len],
    })
}

fn nonce(packet: &[u8]) -> Nonce {
    let mut out = [0u8; 12];
    out.copy_from_slice(&packet[12..24]);
    out
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
