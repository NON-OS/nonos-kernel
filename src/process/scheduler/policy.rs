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

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::policy_types::*;

static SCHED_REGISTRY: Mutex<BTreeMap<u32, SchedAttr>> = Mutex::new(BTreeMap::new());

static POLICY_CHANGES: AtomicU64 = AtomicU64::new(0);
static AFFINITY_CHANGES: AtomicU64 = AtomicU64::new(0);
static PRIORITY_CHANGES: AtomicU64 = AtomicU64::new(0);

pub fn get_sched_attr(pid: u32) -> SchedAttr {
    let registry = SCHED_REGISTRY.lock();
    registry.get(&pid).cloned().unwrap_or_default()
}

pub fn set_sched_attr(pid: u32, attr: SchedAttr) {
    let mut registry = SCHED_REGISTRY.lock();
    registry.insert(pid, attr);
    POLICY_CHANGES.fetch_add(1, Ordering::Relaxed);
}

pub fn get_policy(pid: u32) -> i32 {
    let registry = SCHED_REGISTRY.lock();
    registry.get(&pid).map(|a| a.policy).unwrap_or(SCHED_NORMAL)
}

pub fn set_policy(pid: u32, policy: i32, priority: i32) -> Result<(), &'static str> {
    match policy {
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => {
            if priority != 0 {
                return Err("EINVAL: non-RT policies require priority 0");
            }
        }
        SCHED_FIFO | SCHED_RR => {
            if priority < SCHED_PRIORITY_MIN || priority > SCHED_PRIORITY_MAX {
                return Err("EINVAL: RT priority out of range 1-99");
            }
        }
        SCHED_DEADLINE => {
            return Err("EINVAL: use sched_setattr for SCHED_DEADLINE");
        }
        _ => {
            return Err("EINVAL: invalid scheduling policy");
        }
    }

    let mut registry = SCHED_REGISTRY.lock();
    let attr = registry.entry(pid).or_insert_with(SchedAttr::default);
    attr.policy = policy;
    attr.rt_priority = priority;
    POLICY_CHANGES.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

pub fn get_priority(pid: u32) -> i32 {
    let registry = SCHED_REGISTRY.lock();
    registry.get(&pid).map(|a| a.rt_priority).unwrap_or(0)
}

pub fn set_priority(pid: u32, priority: i32) -> Result<(), &'static str> {
    let mut registry = SCHED_REGISTRY.lock();
    let attr = registry.entry(pid).or_insert_with(SchedAttr::default);

    if attr.is_realtime() {
        if priority < SCHED_PRIORITY_MIN || priority > SCHED_PRIORITY_MAX {
            return Err("EINVAL: RT priority out of range 1-99");
        }
    } else if priority != 0 {
        return Err("EINVAL: non-RT policies require priority 0");
    }

    attr.rt_priority = priority;
    PRIORITY_CHANGES.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

pub fn get_nice(pid: u32) -> i32 {
    let registry = SCHED_REGISTRY.lock();
    registry.get(&pid).map(|a| a.nice).unwrap_or(NICE_DEFAULT)
}

pub fn set_nice(pid: u32, nice: i32) -> Result<(), &'static str> {
    if nice < NICE_MIN || nice > NICE_MAX {
        return Err("EINVAL: nice value out of range -20 to 19");
    }

    let mut registry = SCHED_REGISTRY.lock();
    let attr = registry.entry(pid).or_insert_with(SchedAttr::default);
    attr.nice = nice;
    PRIORITY_CHANGES.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

pub fn get_affinity(pid: u32) -> u64 {
    let registry = SCHED_REGISTRY.lock();
    registry.get(&pid).map(|a| a.cpu_affinity).unwrap_or(0xFFFF_FFFF_FFFF_FFFF)
}

pub fn set_affinity(pid: u32, mask: u64) -> Result<(), &'static str> {
    if mask == 0 {
        return Err("EINVAL: empty CPU affinity mask");
    }

    let available_cpus = get_online_cpu_mask();
    if (mask & available_cpus) == 0 {
        return Err("EINVAL: no overlap with online CPUs");
    }

    let mut registry = SCHED_REGISTRY.lock();
    let attr = registry.entry(pid).or_insert_with(SchedAttr::default);
    attr.cpu_affinity = mask & available_cpus;
    AFFINITY_CHANGES.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

pub fn get_ioprio(pid: u32) -> u16 {
    let registry = SCHED_REGISTRY.lock();
    registry.get(&pid).map(|a| a.ioprio).unwrap_or(encode_ioprio(IOPRIO_CLASS_BE, 4))
}

pub fn set_ioprio(pid: u32, ioprio: u16) -> Result<(), &'static str> {
    let class = decode_ioprio_class(ioprio);
    let level = decode_ioprio_level(ioprio);

    if class < IOPRIO_CLASS_NONE || class > IOPRIO_CLASS_IDLE {
        return Err("EINVAL: invalid I/O priority class");
    }

    if (class == IOPRIO_CLASS_RT || class == IOPRIO_CLASS_BE) && level > 7 {
        return Err("EINVAL: invalid I/O priority level");
    }

    let mut registry = SCHED_REGISTRY.lock();
    let attr = registry.entry(pid).or_insert_with(SchedAttr::default);
    attr.ioprio = ioprio;

    Ok(())
}

pub fn remove_process(pid: u32) {
    let mut registry = SCHED_REGISTRY.lock();
    registry.remove(&pid);
}

pub fn init_process(pid: u32, parent_pid: Option<u32>) {
    let mut registry = SCHED_REGISTRY.lock();

    let attr = if let Some(ppid) = parent_pid {
        if let Some(parent_attr) = registry.get(&ppid) {
            let mut inherited = parent_attr.clone();
            if (inherited.flags & SCHED_FLAG_RESET_ON_FORK) != 0 {
                inherited.policy = SCHED_NORMAL;
                inherited.rt_priority = 0;
            }
            inherited
        } else {
            SchedAttr::default()
        }
    } else {
        SchedAttr::default()
    };

    registry.insert(pid, attr);
}

static ONLINE_CPUS: AtomicU32 = AtomicU32::new(1);

pub fn get_online_cpu_count() -> u32 {
    ONLINE_CPUS.load(Ordering::Relaxed)
}

pub fn get_online_cpu_mask() -> u64 {
    let count = ONLINE_CPUS.load(Ordering::Relaxed);
    if count >= 64 {
        u64::MAX
    } else {
        (1u64 << count) - 1
    }
}

pub fn set_online_cpu_count(count: u32) {
    ONLINE_CPUS.store(count.max(1), Ordering::Relaxed);
}

pub fn get_stats() -> SchedPolicyStats {
    let registry = SCHED_REGISTRY.lock();
    let mut stats = SchedPolicyStats::default();

    for attr in registry.values() {
        match attr.policy {
            SCHED_NORMAL => stats.normal_count += 1,
            SCHED_FIFO => stats.fifo_count += 1,
            SCHED_RR => stats.rr_count += 1,
            SCHED_BATCH => stats.batch_count += 1,
            SCHED_IDLE => stats.idle_count += 1,
            SCHED_DEADLINE => stats.deadline_count += 1,
            _ => {}
        }
    }

    stats.total_processes = registry.len() as u32;
    stats.policy_changes = POLICY_CHANGES.load(Ordering::Relaxed);
    stats.affinity_changes = AFFINITY_CHANGES.load(Ordering::Relaxed);
    stats.priority_changes = PRIORITY_CHANGES.load(Ordering::Relaxed);

    stats
}
