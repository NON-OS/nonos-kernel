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
use super::cpu::CpuLimit;
use super::io::IoLimit;
use super::memory::MemoryLimit;
use super::pids::PidsLimit;
use super::types::{CgroupError, CgroupId, CgroupStats};
use alloc::collections::{BTreeMap, BTreeSet};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

pub struct Cgroup {
    pub id: CgroupId,
    pub parent: Option<CgroupId>,
    pub processes: BTreeSet<u64>,
    pub memory_limit: Option<MemoryLimit>,
    pub cpu_limit: Option<CpuLimit>,
    pub pids_limit: Option<PidsLimit>,
    pub io_limit: Option<IoLimit>,
    pub stats: CgroupStats,
}

static CGROUPS: RwLock<BTreeMap<CgroupId, Cgroup>> = RwLock::new(BTreeMap::new());
static PROCESS_CGROUP: RwLock<BTreeMap<u64, CgroupId>> = RwLock::new(BTreeMap::new());
static NEXT_CGROUP_ID: AtomicU64 = AtomicU64::new(1);

pub fn create_cgroup(parent: Option<CgroupId>) -> Result<CgroupId, CgroupError> {
    let id = NEXT_CGROUP_ID.fetch_add(1, Ordering::Relaxed);
    let cgroup = Cgroup {
        id,
        parent,
        processes: BTreeSet::new(),
        memory_limit: None,
        cpu_limit: None,
        pids_limit: None,
        io_limit: None,
        stats: CgroupStats::default(),
    };
    CGROUPS.write().insert(id, cgroup);
    Ok(id)
}

pub fn delete_cgroup(id: CgroupId) -> Result<(), CgroupError> {
    let mut cgroups = CGROUPS.write();
    let cg = cgroups.get(&id).ok_or(CgroupError::NotFound)?;
    if !cg.processes.is_empty() {
        return Err(CgroupError::NotEmpty);
    }
    cgroups.remove(&id);
    Ok(())
}

pub fn attach_process(cgroup_id: CgroupId, pid: u64) -> Result<(), CgroupError> {
    let mut cgroups = CGROUPS.write();
    let cg = cgroups.get_mut(&cgroup_id).ok_or(CgroupError::NotFound)?;
    if let Some(limit) = &cg.pids_limit {
        if cg.processes.len() as u64 >= limit.max {
            return Err(CgroupError::LimitExceeded);
        }
    }
    cg.processes.insert(pid);
    cg.stats.pids_current.fetch_add(1, Ordering::Relaxed);
    drop(cgroups);
    PROCESS_CGROUP.write().insert(pid, cgroup_id);
    Ok(())
}

pub fn detach_process(pid: u64) -> Result<(), CgroupError> {
    let cgroup_id = PROCESS_CGROUP.write().remove(&pid).ok_or(CgroupError::NotFound)?;
    let mut cgroups = CGROUPS.write();
    if let Some(cg) = cgroups.get_mut(&cgroup_id) {
        cg.processes.remove(&pid);
        cg.stats.pids_current.fetch_sub(1, Ordering::Relaxed);
    }
    Ok(())
}

pub fn get_cgroup_for_pid(pid: u64) -> Option<CgroupId> {
    PROCESS_CGROUP.read().get(&pid).copied()
}

pub(super) fn get_cgroup(id: CgroupId) -> Option<Cgroup> {
    CGROUPS.read().get(&id).map(|cg| Cgroup {
        id: cg.id,
        parent: cg.parent,
        processes: cg.processes.clone(),
        memory_limit: cg.memory_limit,
        cpu_limit: cg.cpu_limit,
        pids_limit: cg.pids_limit,
        io_limit: cg.io_limit,
        stats: CgroupStats::default(),
    })
}

pub(super) fn update_cgroup<F: FnOnce(&mut Cgroup)>(id: CgroupId, f: F) -> Result<(), CgroupError> {
    let mut cgroups = CGROUPS.write();
    let cg = cgroups.get_mut(&id).ok_or(CgroupError::NotFound)?;
    f(cg);
    Ok(())
}
