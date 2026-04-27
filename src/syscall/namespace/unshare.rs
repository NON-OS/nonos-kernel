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
use super::types::{NamespaceFlags, NamespaceType, CLONE_NEWIPC, CLONE_NEWNS, CLONE_NEWUTS};
use super::types::{CLONE_NEWCGROUP, CLONE_NEWNET, CLONE_NEWPID, CLONE_NEWUSER};
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;

pub fn handle_unshare(flags: u64) -> SyscallResult {
    let ns_flags = NamespaceFlags(flags);
    if !ns_flags.is_valid() {
        return errno(22);
    }
    let pid = crate::process::current_pid().unwrap_or(1) as u64;
    let ns_types = [
        (CLONE_NEWNS, NamespaceType::Mount),
        (CLONE_NEWUTS, NamespaceType::Uts),
        (CLONE_NEWIPC, NamespaceType::Ipc),
        (CLONE_NEWUSER, NamespaceType::User),
        (CLONE_NEWPID, NamespaceType::Pid),
        (CLONE_NEWNET, NamespaceType::Net),
        (CLONE_NEWCGROUP, NamespaceType::Cgroup),
    ];
    for (flag, ns_type) in ns_types.iter() {
        if flags & flag != 0 {
            if let Err(e) = NamespaceManager::unshare(pid, *ns_type) {
                return errno(e);
            }
        }
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
