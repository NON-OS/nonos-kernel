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

use crate::sched::*;
use crate::test::framework::TestResult;

fn dummy_task_fn() {}

pub(crate) fn test_task_spawn_creates_task() -> TestResult {
    let task = Task::spawn("test_task", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    if task.name != "test_task" {
        return TestResult::Fail;
    }
    if task.priority != Priority::Normal {
        return TestResult::Fail;
    }
    if task.is_complete() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_spawn_with_different_priorities() -> TestResult {
    let idle = Task::spawn("idle", dummy_task_fn, Priority::Idle, CpuAffinity::any());
    let realtime = Task::spawn("rt", dummy_task_fn, Priority::RealTime, CpuAffinity::any());
    if idle.priority != Priority::Idle {
        return TestResult::Fail;
    }
    if realtime.priority != Priority::RealTime {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_id_starts_at_zero() -> TestResult {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    if task.id != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_has_function() -> TestResult {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    if task.func.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_is_complete_initially_false() -> TestResult {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    if task.is_complete() {
        return TestResult::Fail;
    }
    if task.complete {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_module_id_none_for_spawned() -> TestResult {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    if task.module_id.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_entry_point_zero_for_spawned() -> TestResult {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    if task.entry_point != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_stack_pointer_zero_for_spawned() -> TestResult {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    if task.stack_pointer != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_low_priority() -> TestResult {
    let task = Task::new_module_task(1, 100, 0x1000, 0x2000, 25);
    if task.id != 1 {
        return TestResult::Fail;
    }
    if task.module_id != Some(100) {
        return TestResult::Fail;
    }
    if task.entry_point != 0x1000 {
        return TestResult::Fail;
    }
    if task.stack_pointer != 0x2000 {
        return TestResult::Fail;
    }
    if task.priority != Priority::Low {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_normal_priority() -> TestResult {
    let task = Task::new_module_task(2, 200, 0x3000, 0x4000, 75);
    if task.priority != Priority::Normal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_high_priority() -> TestResult {
    let task = Task::new_module_task(3, 300, 0x5000, 0x6000, 125);
    if task.priority != Priority::High {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_critical_priority() -> TestResult {
    let task = Task::new_module_task(4, 400, 0x7000, 0x8000, 175);
    if task.priority != Priority::Critical {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_realtime_priority() -> TestResult {
    let task = Task::new_module_task(5, 500, 0x9000, 0xA000, 255);
    if task.priority != Priority::RealTime {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_priority_boundary_50() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    if task.priority != Priority::Low {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_priority_boundary_51() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 51);
    if task.priority != Priority::Normal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_priority_boundary_100() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 100);
    if task.priority != Priority::Normal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_priority_boundary_101() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 101);
    if task.priority != Priority::High {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_priority_boundary_150() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 150);
    if task.priority != Priority::High {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_priority_boundary_151() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 151);
    if task.priority != Priority::Critical {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_priority_boundary_200() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 200);
    if task.priority != Priority::Critical {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_priority_boundary_201() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 201);
    if task.priority != Priority::RealTime {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_name() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    if task.name != "module_task" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_func_is_none() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    if task.func.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_not_complete() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    if task.is_complete() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_new_module_task_affinity_any() -> TestResult {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    if task.affinity.allowed_cpus.len() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_affinity_any() -> TestResult {
    let affinity = CpuAffinity::any();
    if affinity.allowed_cpus.len() != 16 {
        return TestResult::Fail;
    }
    for i in 0..16 {
        if !affinity.allowed_cpus.contains(&i) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_affinity_new_single() -> TestResult {
    let affinity = CpuAffinity::new(alloc::vec![0]);
    if affinity.allowed_cpus.len() != 1 {
        return TestResult::Fail;
    }
    if !affinity.allowed_cpus.contains(&0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_affinity_new_multiple() -> TestResult {
    let affinity = CpuAffinity::new(alloc::vec![0, 2, 4, 6]);
    if affinity.allowed_cpus.len() != 4 {
        return TestResult::Fail;
    }
    if !affinity.allowed_cpus.contains(&0) {
        return TestResult::Fail;
    }
    if !affinity.allowed_cpus.contains(&2) {
        return TestResult::Fail;
    }
    if !affinity.allowed_cpus.contains(&4) {
        return TestResult::Fail;
    }
    if !affinity.allowed_cpus.contains(&6) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_affinity_new_empty() -> TestResult {
    let affinity = CpuAffinity::new(alloc::vec![]);
    if affinity.allowed_cpus.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_affinity_clone() -> TestResult {
    let affinity1 = CpuAffinity::new(alloc::vec![1, 3, 5]);
    let affinity2 = affinity1.clone();
    if affinity1.allowed_cpus != affinity2.allowed_cpus {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_affinity_debug() -> TestResult {
    let affinity = CpuAffinity::new(alloc::vec![0, 1]);
    let debug_str = alloc::format!("{:?}", affinity);
    if !debug_str.contains("CpuAffinity") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_with_custom_affinity() -> TestResult {
    let affinity = CpuAffinity::new(alloc::vec![0, 1, 2, 3]);
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, affinity);
    if task.affinity.allowed_cpus.len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
