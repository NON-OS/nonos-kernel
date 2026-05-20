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

use crate::crypto::{fill_random, seal, Key, Nonce, TAG_BYTES};
use crate::protocol::WIRE_PACKET_MAX;

use super::header::{WIRE_MAGIC, WIRE_VERSION};
use super::types::{PacketError, HEADER_LEN};

pub fn encode(
    session_id: u32,
    flags: u8,
    key: &Key,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, PacketError> {
    let needed = HEADER_LEN + plaintext.len() + TAG_BYTES;
    if out.len() < needed || needed > WIRE_PACKET_MAX {
        return Err(PacketError::BadLength);
    }
    let mut nonce: Nonce = [0; 12];
    fill_random(&mut nonce).map_err(|_| PacketError::Crypto)?;
    let cipher_len =
        seal(key, &nonce, plaintext, &mut out[HEADER_LEN..]).map_err(|_| PacketError::Crypto)?;
    write_header(out, session_id, flags, nonce, cipher_len as u16);
    Ok(HEADER_LEN + cipher_len)
}

fn write_header(out: &mut [u8], session_id: u32, flags: u8, nonce: Nonce, len: u16) {
    out[0..4].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
    out[4] = WIRE_VERSION;
    out[5] = flags;
    out[6..8].copy_from_slice(&0u16.to_le_bytes());
    out[8..12].copy_from_slice(&session_id.to_le_bytes());
    out[12..24].copy_from_slice(&nonce);
    out[6..8].copy_from_slice(&len.to_le_bytes());
}
