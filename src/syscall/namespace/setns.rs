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

use super::manager::NamespaceManager;
use super::types::NamespaceType;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;

pub fn handle_setns(fd: i32, nstype: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(1) as u64;
    let ns_type = match NamespaceType::from_flag(nstype) {
        Some(t) => t,
        None => {
            if nstype == 0 {
                return errno(22);
            }
            return errno(22);
        }
    };
    let target_ns_id = fd as u64;
    match NamespaceManager::setns(pid, ns_type, target_ns_id) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(e) => errno(e),
    }
}
