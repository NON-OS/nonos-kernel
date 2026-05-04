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

use super::super::capability::gate_read;
use super::super::error::EntropyCapsuleError;
use super::super::protocol::{encode_request, OP_GET_STATS};
use super::seq::next_request_id;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy)]
pub struct EntropyStats {
    pub uptime_requests: u64,
    pub bytes_served: u64,
    pub last_reseed_request: u64,
    pub source_failures: u64,
}

pub fn get_stats() -> Result<EntropyStats, EntropyCapsuleError> {
    let _caller = gate_read()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_GET_STATS, 0, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(EntropyCapsuleError::ProtocolMismatch);
    }
    if resp.body.len() != 32 {
        return Err(EntropyCapsuleError::ProtocolMismatch);
    }
    let b = &resp.body;
    Ok(EntropyStats {
        uptime_requests: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        bytes_served: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        last_reseed_request: u64::from_le_bytes([
            b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23],
        ]),
        source_failures: u64::from_le_bytes([
            b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31],
        ]),
    })
}
