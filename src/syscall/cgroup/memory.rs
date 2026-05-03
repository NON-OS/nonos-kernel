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

use super::controller::{get_cgroup_for_pid, update_cgroup};
use super::types::{CgroupError, CgroupId};
use core::sync::atomic::Ordering;

#[derive(Debug, Clone, Copy)]
pub struct MemoryLimit {
    pub max: u64,
    pub high: u64,
    pub low: u64,
    pub swap_max: u64,
    pub oom_kill_disable: bool,
}

impl Default for MemoryLimit {
    fn default() -> Self {
        Self { max: u64::MAX, high: u64::MAX, low: 0, swap_max: u64::MAX, oom_kill_disable: false }
    }
}

pub fn set_memory_limit(cgroup_id: CgroupId, limit: MemoryLimit) -> Result<(), CgroupError> {
    if limit.low > limit.high || limit.high > limit.max {
        return Err(CgroupError::InvalidLimit);
    }
    update_cgroup(cgroup_id, |cg| {
        cg.memory_limit = Some(limit);
    })
}

pub fn get_memory_usage(cgroup_id: CgroupId) -> Result<u64, CgroupError> {
    let cg = super::controller::get_cgroup(cgroup_id).ok_or(CgroupError::NotFound)?;
    Ok(cg.stats.memory_current.load(Ordering::Relaxed))
}

pub fn check_memory_limit(pid: u64, requested: u64) -> Result<(), CgroupError> {
    let cgroup_id = get_cgroup_for_pid(pid).ok_or(CgroupError::NotFound)?;
    let cg = super::controller::get_cgroup(cgroup_id).ok_or(CgroupError::NotFound)?;
    if let Some(limit) = cg.memory_limit {
        let current = cg.stats.memory_current.load(Ordering::Relaxed);
        if current.saturating_add(requested) > limit.max {
            if !limit.oom_kill_disable {
                cg.stats.oom_kills.fetch_add(1, Ordering::Relaxed);
            }
            return Err(CgroupError::LimitExceeded);
        }
    }
    Ok(())
}

pub fn account_memory(pid: u64, delta: i64) {
    if let Some(cgroup_id) = get_cgroup_for_pid(pid) {
        if let Some(cg) = super::controller::get_cgroup(cgroup_id) {
            if delta > 0 {
                let new = cg.stats.memory_current.fetch_add(delta as u64, Ordering::Relaxed)
                    + delta as u64;
                let peak = cg.stats.memory_peak.load(Ordering::Relaxed);
                if new > peak {
                    cg.stats.memory_peak.store(new, Ordering::Relaxed);
                }
            } else {
                cg.stats.memory_current.fetch_sub((-delta) as u64, Ordering::Relaxed);
            }
        }
    }
}
