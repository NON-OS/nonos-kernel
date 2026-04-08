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

use core::sync::atomic::Ordering;
use super::types::{CgroupId, CgroupError};
use super::controller::{get_cgroup_for_pid, update_cgroup};

#[derive(Debug, Clone, Copy)]
pub struct PidsLimit { pub max: u64 }

impl Default for PidsLimit { fn default() -> Self { Self { max: u64::MAX } } }

pub fn set_pids_limit(cgroup_id: CgroupId, limit: PidsLimit) -> Result<(), CgroupError> {
    if limit.max == 0 { return Err(CgroupError::InvalidLimit); }
    update_cgroup(cgroup_id, |cg| { cg.pids_limit = Some(limit); })
}

pub fn get_pids_count(cgroup_id: CgroupId) -> Result<u64, CgroupError> {
    let cg = super::controller::get_cgroup(cgroup_id).ok_or(CgroupError::NotFound)?;
    Ok(cg.stats.pids_current.load(Ordering::Relaxed))
}

pub fn check_pids_limit(pid: u64) -> Result<bool, CgroupError> {
    let cgroup_id = get_cgroup_for_pid(pid).ok_or(CgroupError::NotFound)?;
    let cg = super::controller::get_cgroup(cgroup_id).ok_or(CgroupError::NotFound)?;
    if let Some(limit) = cg.pids_limit {
        let current = cg.stats.pids_current.load(Ordering::Relaxed);
        if current >= limit.max { return Ok(false); }
    }
    Ok(true)
}

pub fn can_fork(pid: u64) -> bool { check_pids_limit(pid).unwrap_or(true) }
