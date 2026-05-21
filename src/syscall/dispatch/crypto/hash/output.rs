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

use crate::syscall::dispatch::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;

pub(super) fn write_or_truncate(digest: &[u8], out: u64, out_len: u64) -> SyscallResult {
    if out == 0 {
        return ok_truncated(digest);
    }
    if out_len as usize != digest.len() {
        return errno(22);
    }
    if copy_to_user(out, digest).is_err() {
        return errno(14);
    }
    SyscallResult { value: digest.len() as i64, capability_consumed: false, audit_required: true }
}

fn ok_truncated(digest: &[u8]) -> SyscallResult {
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&digest[..8]);
    SyscallResult {
        value: u64::from_le_bytes(id_bytes) as i64,
        capability_consumed: false,
        audit_required: false,
    }
}
