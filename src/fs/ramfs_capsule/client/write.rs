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

use super::super::error::CapsuleFsError;
use super::super::protocol::encode_write;
use super::super::state;
use super::seq::next;
use super::transport::round_trip;

pub fn write(
    handle: u64,
    generation: u64,
    offset: u64,
    data: &[u8],
) -> Result<usize, CapsuleFsError> {
    if generation != state::current_generation() {
        return Err(CapsuleFsError::StaleGeneration);
    }
    let seq = next();
    let resp = round_trip(seq, encode_write(seq, handle, offset, data))?;
    if resp.status < 0 {
        return Err(map_errno(resp.status));
    }
    Ok(resp.status as usize)
}

fn map_errno(status: i32) -> CapsuleFsError {
    match status {
        -2 => CapsuleFsError::NotFound,
        -22 => CapsuleFsError::InvalidArgument,
        _ => CapsuleFsError::Io,
    }
}
