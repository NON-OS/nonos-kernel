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

use super::types::ProtectionKey;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;

pub fn handle_pkey_mprotect(addr: u64, len: u64, prot: i32, pkey: i32) -> SyscallResult {
    if !ProtectionKey::is_valid(pkey) && pkey != -1 {
        return errno(22);
    }
    let result = crate::syscall::extended::memory::handle_mprotect(addr, len, prot as u64);
    if result.value < 0 {
        return result;
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
