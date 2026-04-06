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

use super::manager::{NamespaceManager, ProcessNamespaces};
use super::types::{NamespaceFlags, NamespaceType};

pub fn clone_namespaces_for_fork(parent_pid: u64, child_pid: u64, flags: u64) {
    NamespaceManager::clone_namespaces(parent_pid, child_pid);
    let ns_flags = NamespaceFlags(flags);
    if ns_flags.has(NamespaceType::Mount) {
        let _ = NamespaceManager::unshare(child_pid, NamespaceType::Mount);
    }
    if ns_flags.has(NamespaceType::Uts) {
        let _ = NamespaceManager::unshare(child_pid, NamespaceType::Uts);
    }
    if ns_flags.has(NamespaceType::Ipc) {
        let _ = NamespaceManager::unshare(child_pid, NamespaceType::Ipc);
    }
    if ns_flags.has(NamespaceType::Net) {
        let _ = NamespaceManager::unshare(child_pid, NamespaceType::Net);
    }
    if ns_flags.has(NamespaceType::User) {
        let _ = NamespaceManager::unshare(child_pid, NamespaceType::User);
    }
    if ns_flags.has(NamespaceType::Pid) {
        let _ = NamespaceManager::unshare(child_pid, NamespaceType::Pid);
    }
    if ns_flags.has(NamespaceType::Cgroup) {
        let _ = NamespaceManager::unshare(child_pid, NamespaceType::Cgroup);
    }
}

pub fn get_all_namespaces(pid: u64) -> ProcessNamespaces {
    ProcessNamespaces {
        mnt_ns: NamespaceManager::get_ns(pid, NamespaceType::Mount),
        uts_ns: NamespaceManager::get_ns(pid, NamespaceType::Uts),
        ipc_ns: NamespaceManager::get_ns(pid, NamespaceType::Ipc),
        user_ns: NamespaceManager::get_ns(pid, NamespaceType::User),
        pid_ns: NamespaceManager::get_ns(pid, NamespaceType::Pid),
        net_ns: NamespaceManager::get_ns(pid, NamespaceType::Net),
        cgroup_ns: NamespaceManager::get_ns(pid, NamespaceType::Cgroup),
    }
}

pub fn share_namespace(from_pid: u64, to_pid: u64, ns_type: NamespaceType) {
    let ns_id = NamespaceManager::get_ns(from_pid, ns_type);
    let _ = NamespaceManager::setns(to_pid, ns_type, ns_id);
}

pub fn cleanup_process_namespaces(pid: u64) {
    let _ = NamespaceManager::setns(pid, NamespaceType::Mount, 0);
    let _ = NamespaceManager::setns(pid, NamespaceType::Uts, 0);
    let _ = NamespaceManager::setns(pid, NamespaceType::Ipc, 0);
    let _ = NamespaceManager::setns(pid, NamespaceType::User, 0);
    let _ = NamespaceManager::setns(pid, NamespaceType::Pid, 0);
    let _ = NamespaceManager::setns(pid, NamespaceType::Net, 0);
    let _ = NamespaceManager::setns(pid, NamespaceType::Cgroup, 0);
}
