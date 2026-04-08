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
pub struct IoLimit {
    pub rbps: u64,
    pub wbps: u64,
    pub riops: u64,
    pub wiops: u64,
}

impl Default for IoLimit {
    fn default() -> Self { Self { rbps: u64::MAX, wbps: u64::MAX, riops: u64::MAX, wiops: u64::MAX } }
}

pub fn set_io_limit(cgroup_id: CgroupId, limit: IoLimit) -> Result<(), CgroupError> {
    update_cgroup(cgroup_id, |cg| { cg.io_limit = Some(limit); })
}

pub fn get_io_stats(cgroup_id: CgroupId) -> Result<(u64, u64), CgroupError> {
    let cg = super::controller::get_cgroup(cgroup_id).ok_or(CgroupError::NotFound)?;
    Ok((cg.stats.io_read_bytes.load(Ordering::Relaxed), cg.stats.io_write_bytes.load(Ordering::Relaxed)))
}

pub fn check_io_limit(pid: u64, is_write: bool, bytes: u64) -> Result<bool, CgroupError> {
    let cgroup_id = get_cgroup_for_pid(pid).ok_or(CgroupError::NotFound)?;
    let cg = super::controller::get_cgroup(cgroup_id).ok_or(CgroupError::NotFound)?;
    if let Some(limit) = cg.io_limit {
        let limit_bps = if is_write { limit.wbps } else { limit.rbps };
        if bytes > limit_bps { return Ok(false); }
    }
    Ok(true)
}

pub fn account_io(pid: u64, is_write: bool, bytes: u64) {
    if let Some(cgroup_id) = get_cgroup_for_pid(pid) {
        if let Some(cg) = super::controller::get_cgroup(cgroup_id) {
            if is_write { cg.stats.io_write_bytes.fetch_add(bytes, Ordering::Relaxed); }
            else { cg.stats.io_read_bytes.fetch_add(bytes, Ordering::Relaxed); }
        }
    }
}
