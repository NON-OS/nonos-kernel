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

use crate::crypto::{fill_random, seal, Key, Nonce};
use crate::protocol::{MIX_PAYLOAD_MAX, NYM_PAYLOAD_BYTES, WIRE_PACKET_MAX};
use crate::route;

use super::header::{
    OFF_FLAGS, OFF_HEADER_RANDOM, OFF_NONCE, OFF_REPLAY_TAG, OFF_SESSION, WIRE_MAGIC, WIRE_VERSION,
};
use super::tag;
use super::types::{PacketError, HEADER_LEN};

pub fn encode(
    session_id: u32,
    flags: u8,
    key: &Key,
    credential: &[u8; 32],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, PacketError> {
    if plaintext.len() > MIX_PAYLOAD_MAX || out.len() < WIRE_PACKET_MAX {
        return Err(PacketError::BadLength);
    }
    let mut nonce: Nonce = [0; 12];
    fill_random(&mut nonce).map_err(|_| PacketError::Crypto)?;
    let mut plain = super::plain::padded_plaintext(plaintext)?;
    out[..WIRE_PACKET_MAX].fill(0);
    write_header_base(out, session_id, flags, nonce);
    write_route_header(out, session_id, flags, key, credential)?;
    let cipher = &mut out[HEADER_LEN..WIRE_PACKET_MAX];
    let n = seal(key, &nonce, &plain, cipher).map_err(|_| PacketError::Crypto)?;
    plain.fill(0);
    if n != NYM_PAYLOAD_BYTES {
        return Err(PacketError::BadLength);
    }
    let replay_tag = tag::compute(session_id, flags, &nonce, cipher)?;
    out[OFF_REPLAY_TAG..OFF_REPLAY_TAG + replay_tag.len()].copy_from_slice(&replay_tag);
    Ok(WIRE_PACKET_MAX)
}

fn write_route_header(
    out: &mut [u8],
    session_id: u32,
    flags: u8,
    key: &Key,
    credential: &[u8; 32],
) -> Result<(), PacketError> {
    let route = route::build(session_id, flags, key, credential)?;
    out[OFF_HEADER_RANDOM..HEADER_LEN].copy_from_slice(&route);
    Ok(())
}

fn write_header_base(out: &mut [u8], session_id: u32, flags: u8, nonce: Nonce) {
    out[0..4].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
    out[4] = WIRE_VERSION;
    out[OFF_FLAGS] = flags;
    out[6..8].copy_from_slice(&0u16.to_le_bytes());
    out[OFF_SESSION..OFF_SESSION + 4].copy_from_slice(&session_id.to_le_bytes());
    out[OFF_NONCE..OFF_NONCE + nonce.len()].copy_from_slice(&nonce);
}
