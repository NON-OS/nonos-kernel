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

use super::super::capability;
use super::super::error::KeyringCapsuleError;
use super::super::protocol::encode_metadata;
use super::super::types::{KeyMetadata, KeyType};
use super::errno;
use super::seq::next;
use super::transport::round_trip;

const META_LEN: usize = 36;

pub fn metadata(id: u32) -> Result<KeyMetadata, KeyringCapsuleError> {
    let caller_pid = capability::gate_caller()?;
    let seq = next();
    let resp = round_trip(seq, encode_metadata(seq, caller_pid, id))?;
    if resp.status < 0 {
        return Err(errno::map(resp.status));
    }
    if resp.payload.len() != META_LEN {
        return Err(KeyringCapsuleError::ProtocolMismatch);
    }
    let p = &resp.payload;
    let key_type = KeyType::from_u8(p[4]).ok_or(KeyringCapsuleError::ProtocolMismatch)?;
    Ok(KeyMetadata {
        id: u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
        key_type,
        size: u16::from_le_bytes([p[5], p[6]]),
        owner_pid: u32::from_le_bytes([p[7], p[8], p[9], p[10]]),
        created_at: u64::from_le_bytes([p[11], p[12], p[13], p[14], p[15], p[16], p[17], p[18]]),
        expires_at: u64::from_le_bytes([p[19], p[20], p[21], p[22], p[23], p[24], p[25], p[26]]),
        use_count: u64::from_le_bytes([p[27], p[28], p[29], p[30], p[31], p[32], p[33], p[34]]),
        locked: p[35] != 0,
    })
}
