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
use super::super::protocol::encode_store;
use super::super::types::KeyType;
use super::errno;
use super::seq::next;
use super::transport::round_trip;

pub fn store(key_type: KeyType, data: &[u8], expires_at: u64) -> Result<u32, KeyringCapsuleError> {
    let caller_pid = capability::gate_caller()?;
    let now = crate::time::timestamp_millis();
    let seq = next();
    let resp =
        round_trip(seq, encode_store(seq, caller_pid, now, expires_at, key_type.to_u8(), data))?;
    if resp.status < 0 {
        return Err(errno::map(resp.status));
    }
    if resp.payload.len() != 4 {
        return Err(KeyringCapsuleError::ProtocolMismatch);
    }
    Ok(u32::from_le_bytes([resp.payload[0], resp.payload[1], resp.payload[2], resp.payload[3]]))
}
