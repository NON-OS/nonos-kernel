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

use alloc::vec::Vec;

use super::super::error::CapsuleFsError;
use super::super::protocol::encode_read;
use super::super::state;
use super::seq::next;
use super::transport::round_trip;

pub fn read(
    handle: u64,
    generation: u64,
    offset: u64,
    count: u32,
) -> Result<Vec<u8>, CapsuleFsError> {
    if generation != state::current_generation() {
        return Err(CapsuleFsError::StaleGeneration);
    }
    let seq = next();
    let resp = round_trip(seq, encode_read(seq, handle, offset, count))?;
    if resp.status < 0 {
        return Err(map_errno(resp.status));
    }
    let bytes_read = resp.status as usize;
    if bytes_read > resp.payload.len() {
        return Err(CapsuleFsError::TransportFailure);
    }
    let mut payload = resp.payload;
    payload.truncate(bytes_read);
    Ok(payload)
}

fn map_errno(status: i32) -> CapsuleFsError {
    match status {
        -2 => CapsuleFsError::NotFound,
        -22 => CapsuleFsError::InvalidArgument,
        _ => CapsuleFsError::Io,
    }
}
