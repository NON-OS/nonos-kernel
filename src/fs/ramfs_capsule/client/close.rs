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
use super::super::protocol::encode_close;
use super::super::state;
use super::seq::next;
use super::transport::round_trip;

// Close on a stale-generation fd is a no-op success: the kernel-side
// fd is being torn down, the remote handle is already invalid because
// the capsule that owned it is gone, and the caller does not need to
// be told the file the kernel forgot was already forgotten.
pub fn close(handle: u64, generation: u64) -> Result<(), CapsuleFsError> {
    if generation != state::current_generation() {
        return Ok(());
    }
    let seq = next();
    let resp = round_trip(seq, encode_close(seq, handle))?;
    if resp.status < 0 {
        return Err(CapsuleFsError::Io);
    }
    Ok(())
}
