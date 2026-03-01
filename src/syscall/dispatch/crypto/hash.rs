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

use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use crate::syscall::dispatch::{errno, require_capability};

pub fn handle_crypto_hash(algo: u64, data: u64, len: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }

    if data == 0 || len == 0 || len > 1024 * 1024 {
        return errno(22);
    }

    let input = unsafe {
        core::slice::from_raw_parts(data as *const u8, len as usize)
    };

    let hash_result = match algo {
        0 => crate::crypto::syscall_blake3_hash(input),
        1 => crate::crypto::sha256_hash(input),
        2 => crate::crypto::sha512_hash(input),
        _ => return errno(22),
    };

    match hash_result {
        Ok(hash_id) => SyscallResult { value: hash_id as i64, capability_consumed: false, audit_required: false },
        Err(_) => errno(5),
    }
}
