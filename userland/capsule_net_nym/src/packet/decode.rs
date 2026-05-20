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
use crate::protocol::WIRE_PACKET_MAX;

use super::header::{OFF_FLAGS, OFF_NONCE, OFF_REPLAY_TAG, OFF_SESSION, WIRE_MAGIC, WIRE_VERSION};
use super::tag;
use super::types::{Decoded, PacketError, HEADER_LEN, REPLAY_TAG_LEN};

pub fn decode(packet: &[u8]) -> Result<Decoded<'_>, PacketError> {
    if packet.len() < HEADER_LEN {
        return Err(PacketError::Short);
    }
    if packet.len() != WIRE_PACKET_MAX {
        return Err(PacketError::BadLength);
    }
    if le32(packet, 0) != WIRE_MAGIC {
        return Err(PacketError::BadMagic);
    }
    if packet[4] != WIRE_VERSION {
        return Err(PacketError::BadVersion);
    }
    let session_id = le32(packet, OFF_SESSION);
    let flags = packet[OFF_FLAGS];
    let replay_tag = replay_tag(packet);
    let ciphertext = &packet[HEADER_LEN..WIRE_PACKET_MAX];
    verify_tag(session_id, flags, &nonce(packet), &replay_tag, ciphertext)?;
    Ok(Decoded { session_id, flags, nonce: nonce(packet), replay_tag, ciphertext })
}

fn nonce(packet: &[u8]) -> Nonce {
    let mut out = [0u8; 12];
    out.copy_from_slice(&packet[OFF_NONCE..OFF_NONCE + 12]);
    out
}

fn replay_tag(packet: &[u8]) -> [u8; REPLAY_TAG_LEN] {
    let mut out = [0u8; REPLAY_TAG_LEN];
    out.copy_from_slice(&packet[OFF_REPLAY_TAG..OFF_REPLAY_TAG + REPLAY_TAG_LEN]);
    out
}

fn verify_tag(
    session_id: u32,
    flags: u8,
    nonce: &Nonce,
    want: &[u8; REPLAY_TAG_LEN],
    ciphertext: &[u8],
) -> Result<(), PacketError> {
    let got = tag::compute(session_id, flags, nonce, ciphertext)?;
    if got == *want {
        Ok(())
    } else {
        Err(PacketError::BadTag)
    }
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
