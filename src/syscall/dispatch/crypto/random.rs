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

extern crate alloc;

use crate::capabilities::Capability;
use crate::syscall::dispatch::{errno, require_capability};
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;

pub fn handle_crypto_random(buf: u64, len: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }
    if buf == 0 || len == 0 || len > 4096 {
        return errno(22);
    }
    let mut buffer = alloc::vec![0u8; len as usize];
    crate::crypto::fill_random(&mut buffer);
    if copy_to_user(buf, &buffer).is_err() {
        return errno(14);
    }
    SyscallResult { value: len as i64, capability_consumed: false, audit_required: false }
}
