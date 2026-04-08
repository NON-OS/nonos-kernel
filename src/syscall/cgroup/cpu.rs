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
pub struct CpuLimit {
    pub quota_usec: u64,
    pub period_usec: u64,
    pub weight: u32,
    pub weight_nice: i32,
}

impl Default for CpuLimit {
    fn default() -> Self { Self { quota_usec: u64::MAX, period_usec: 100_000, weight: 100, weight_nice: 0 } }
}

pub fn set_cpu_limit(cgroup_id: CgroupId, limit: CpuLimit) -> Result<(), CgroupError> {
    if limit.period_usec == 0 || limit.weight == 0 { return Err(CgroupError::InvalidLimit); }
    update_cgroup(cgroup_id, |cg| { cg.cpu_limit = Some(limit); })
}

pub fn get_cpu_usage(cgroup_id: CgroupId) -> Result<u64, CgroupError> {
    let cg = super::controller::get_cgroup(cgroup_id).ok_or(CgroupError::NotFound)?;
    Ok(cg.stats.cpu_usage_usec.load(Ordering::Relaxed))
}

pub fn check_cpu_limit(pid: u64, period_start: u64) -> Result<bool, CgroupError> {
    let cgroup_id = get_cgroup_for_pid(pid).ok_or(CgroupError::NotFound)?;
    let cg = super::controller::get_cgroup(cgroup_id).ok_or(CgroupError::NotFound)?;
    if let Some(limit) = cg.cpu_limit {
        if limit.quota_usec == u64::MAX { return Ok(true); }
        let usage = cg.stats.cpu_usage_usec.load(Ordering::Relaxed);
        let period_usage = usage.saturating_sub(period_start);
        if period_usage >= limit.quota_usec {
            cg.stats.throttled_usec.fetch_add(limit.period_usec, Ordering::Relaxed);
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn account_cpu(pid: u64, usec: u64) {
    if let Some(cgroup_id) = get_cgroup_for_pid(pid) {
        if let Some(cg) = super::controller::get_cgroup(cgroup_id) {
            cg.stats.cpu_usage_usec.fetch_add(usec, Ordering::Relaxed);
        }
    }
}

pub fn get_cpu_weight(pid: u64) -> u32 {
    get_cgroup_for_pid(pid)
        .and_then(|id| super::controller::get_cgroup(id))
        .and_then(|cg| cg.cpu_limit)
        .map(|l| l.weight)
        .unwrap_or(100)
}
