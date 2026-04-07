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

use super::priority::{Priority, SchedPolicy};
use super::affinity::CpuAffinity;
use super::deadline_types::{DeadlineParams, DeadlineFlags};

pub struct Task {
    pub id: u64,
    pub name: &'static str,
    pub func: Option<fn()>,
    pub priority: Priority,
    pub affinity: CpuAffinity,
    pub complete: bool,
    pub module_id: Option<u64>,
    pub entry_point: u64,
    pub stack_pointer: u64,
    pub policy: SchedPolicy,
    pub deadline_params: Option<DeadlineParams>,
    pub exec_start: u64,
    pub sum_exec_runtime: u64,
}

impl Task {
    pub fn spawn(name: &'static str, func: fn(), priority: Priority, affinity: CpuAffinity) -> Self {
        Self {
            id: 0, name, func: Some(func), priority, affinity, complete: false,
            module_id: None, entry_point: 0, stack_pointer: 0,
            policy: SchedPolicy::Normal, deadline_params: None, exec_start: 0, sum_exec_runtime: 0,
        }
    }

    pub fn spawn_deadline(name: &'static str, func: fn(), affinity: CpuAffinity, runtime: u64, deadline: u64, period: u64) -> Self {
        Self {
            id: 0, name, func: Some(func), priority: Priority::Deadline, affinity, complete: false,
            module_id: None, entry_point: 0, stack_pointer: 0, policy: SchedPolicy::Deadline,
            deadline_params: Some(DeadlineParams::new(runtime, deadline, period)), exec_start: 0, sum_exec_runtime: 0,
        }
    }

    pub fn new_module_task(task_id: u64, module_id: u64, entry_point: u64, stack_pointer: u64, priority: u8) -> Self {
        let prio = match priority {
            0..=50 => Priority::Low, 51..=100 => Priority::Normal,
            101..=150 => Priority::High, 151..=200 => Priority::Critical, _ => Priority::RealTime,
        };
        Self {
            id: task_id, name: "module_task", func: None, priority: prio, affinity: CpuAffinity::any(),
            complete: false, module_id: Some(module_id), entry_point, stack_pointer,
            policy: SchedPolicy::Normal, deadline_params: None, exec_start: 0, sum_exec_runtime: 0,
        }
    }

    pub fn is_complete(&self) -> bool { self.complete }
    pub fn is_deadline(&self) -> bool { self.policy == SchedPolicy::Deadline && self.deadline_params.is_some() }
    pub fn get_abs_deadline(&self) -> u64 { self.deadline_params.as_ref().map(|d| d.abs_deadline).unwrap_or(u64::MAX) }
    pub fn is_throttled(&self) -> bool { self.deadline_params.as_ref().map(|d| d.flags.contains(DeadlineFlags::THROTTLED)).unwrap_or(false) }
}
