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

use super::types::NamespaceType;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static NS_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static PROCESS_NS: Mutex<BTreeMap<u64, ProcessNamespaces>> = Mutex::new(BTreeMap::new());

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessNamespaces {
    pub mnt_ns: u64,
    pub uts_ns: u64,
    pub ipc_ns: u64,
    pub user_ns: u64,
    pub pid_ns: u64,
    pub net_ns: u64,
    pub cgroup_ns: u64,
}

pub struct NamespaceManager;

impl NamespaceManager {
    pub fn init_process(pid: u64) {
        let mut ns_map = PROCESS_NS.lock();
        if !ns_map.contains_key(&pid) {
            ns_map.insert(pid, ProcessNamespaces::default());
        }
    }

    pub fn unshare(pid: u64, ns_type: NamespaceType) -> Result<u64, i32> {
        let new_ns_id = NS_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut ns_map = PROCESS_NS.lock();
        let ns = ns_map.entry(pid).or_insert(ProcessNamespaces::default());
        match ns_type {
            NamespaceType::Mount => ns.mnt_ns = new_ns_id,
            NamespaceType::Uts => ns.uts_ns = new_ns_id,
            NamespaceType::Ipc => ns.ipc_ns = new_ns_id,
            NamespaceType::User => ns.user_ns = new_ns_id,
            NamespaceType::Pid => ns.pid_ns = new_ns_id,
            NamespaceType::Net => ns.net_ns = new_ns_id,
            NamespaceType::Cgroup => ns.cgroup_ns = new_ns_id,
        }
        Ok(new_ns_id)
    }

    pub fn setns(pid: u64, ns_type: NamespaceType, ns_id: u64) -> Result<(), i32> {
        let mut ns_map = PROCESS_NS.lock();
        let ns = ns_map.entry(pid).or_insert(ProcessNamespaces::default());
        match ns_type {
            NamespaceType::Mount => ns.mnt_ns = ns_id,
            NamespaceType::Uts => ns.uts_ns = ns_id,
            NamespaceType::Ipc => ns.ipc_ns = ns_id,
            NamespaceType::User => ns.user_ns = ns_id,
            NamespaceType::Pid => ns.pid_ns = ns_id,
            NamespaceType::Net => ns.net_ns = ns_id,
            NamespaceType::Cgroup => ns.cgroup_ns = ns_id,
        }
        Ok(())
    }

    pub fn get_ns(pid: u64, ns_type: NamespaceType) -> u64 {
        let ns_map = PROCESS_NS.lock();
        let ns = ns_map.get(&pid).copied().unwrap_or_default();
        match ns_type {
            NamespaceType::Mount => ns.mnt_ns,
            NamespaceType::Uts => ns.uts_ns,
            NamespaceType::Ipc => ns.ipc_ns,
            NamespaceType::User => ns.user_ns,
            NamespaceType::Pid => ns.pid_ns,
            NamespaceType::Net => ns.net_ns,
            NamespaceType::Cgroup => ns.cgroup_ns,
        }
    }

    pub fn clone_namespaces(parent_pid: u64, child_pid: u64) {
        let ns_map = PROCESS_NS.lock();
        if let Some(parent_ns) = ns_map.get(&parent_pid) {
            let mut ns_map = PROCESS_NS.lock();
            ns_map.insert(child_pid, *parent_ns);
        }
    }
}
