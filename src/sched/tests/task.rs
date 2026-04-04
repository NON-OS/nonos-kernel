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

fn dummy_task_fn() {}

#[test]
fn test_task_spawn_creates_task() {
    let task = Task::spawn("test_task", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    assert_eq!(task.name, "test_task");
    assert_eq!(task.priority, Priority::Normal);
    assert!(!task.is_complete());
}

#[test]
fn test_task_spawn_with_different_priorities() {
    let idle = Task::spawn("idle", dummy_task_fn, Priority::Idle, CpuAffinity::any());
    let realtime = Task::spawn("rt", dummy_task_fn, Priority::RealTime, CpuAffinity::any());
    assert_eq!(idle.priority, Priority::Idle);
    assert_eq!(realtime.priority, Priority::RealTime);
}

#[test]
fn test_task_id_starts_at_zero() {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    assert_eq!(task.id, 0);
}

#[test]
fn test_task_has_function() {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    assert!(task.func.is_some());
}

#[test]
fn test_task_is_complete_initially_false() {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    assert!(!task.is_complete());
    assert!(!task.complete);
}

#[test]
fn test_task_module_id_none_for_spawned() {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    assert!(task.module_id.is_none());
}

#[test]
fn test_task_entry_point_zero_for_spawned() {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    assert_eq!(task.entry_point, 0);
}

#[test]
fn test_task_stack_pointer_zero_for_spawned() {
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, CpuAffinity::any());
    assert_eq!(task.stack_pointer, 0);
}

#[test]
fn test_new_module_task_low_priority() {
    let task = Task::new_module_task(1, 100, 0x1000, 0x2000, 25);
    assert_eq!(task.id, 1);
    assert_eq!(task.module_id, Some(100));
    assert_eq!(task.entry_point, 0x1000);
    assert_eq!(task.stack_pointer, 0x2000);
    assert_eq!(task.priority, Priority::Low);
}

#[test]
fn test_new_module_task_normal_priority() {
    let task = Task::new_module_task(2, 200, 0x3000, 0x4000, 75);
    assert_eq!(task.priority, Priority::Normal);
}

#[test]
fn test_new_module_task_high_priority() {
    let task = Task::new_module_task(3, 300, 0x5000, 0x6000, 125);
    assert_eq!(task.priority, Priority::High);
}

#[test]
fn test_new_module_task_critical_priority() {
    let task = Task::new_module_task(4, 400, 0x7000, 0x8000, 175);
    assert_eq!(task.priority, Priority::Critical);
}

#[test]
fn test_new_module_task_realtime_priority() {
    let task = Task::new_module_task(5, 500, 0x9000, 0xA000, 255);
    assert_eq!(task.priority, Priority::RealTime);
}

#[test]
fn test_new_module_task_priority_boundary_50() {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    assert_eq!(task.priority, Priority::Low);
}

#[test]
fn test_new_module_task_priority_boundary_51() {
    let task = Task::new_module_task(1, 1, 0, 0, 51);
    assert_eq!(task.priority, Priority::Normal);
}

#[test]
fn test_new_module_task_priority_boundary_100() {
    let task = Task::new_module_task(1, 1, 0, 0, 100);
    assert_eq!(task.priority, Priority::Normal);
}

#[test]
fn test_new_module_task_priority_boundary_101() {
    let task = Task::new_module_task(1, 1, 0, 0, 101);
    assert_eq!(task.priority, Priority::High);
}

#[test]
fn test_new_module_task_priority_boundary_150() {
    let task = Task::new_module_task(1, 1, 0, 0, 150);
    assert_eq!(task.priority, Priority::High);
}

#[test]
fn test_new_module_task_priority_boundary_151() {
    let task = Task::new_module_task(1, 1, 0, 0, 151);
    assert_eq!(task.priority, Priority::Critical);
}

#[test]
fn test_new_module_task_priority_boundary_200() {
    let task = Task::new_module_task(1, 1, 0, 0, 200);
    assert_eq!(task.priority, Priority::Critical);
}

#[test]
fn test_new_module_task_priority_boundary_201() {
    let task = Task::new_module_task(1, 1, 0, 0, 201);
    assert_eq!(task.priority, Priority::RealTime);
}

#[test]
fn test_new_module_task_name() {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    assert_eq!(task.name, "module_task");
}

#[test]
fn test_new_module_task_func_is_none() {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    assert!(task.func.is_none());
}

#[test]
fn test_new_module_task_not_complete() {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    assert!(!task.is_complete());
}

#[test]
fn test_new_module_task_affinity_any() {
    let task = Task::new_module_task(1, 1, 0, 0, 50);
    assert_eq!(task.affinity.allowed_cpus.len(), 16);
}

#[test]
fn test_cpu_affinity_any() {
    let affinity = CpuAffinity::any();
    assert_eq!(affinity.allowed_cpus.len(), 16);
    for i in 0..16 {
        assert!(affinity.allowed_cpus.contains(&i));
    }
}

#[test]
fn test_cpu_affinity_new_single() {
    let affinity = CpuAffinity::new(alloc::vec![0]);
    assert_eq!(affinity.allowed_cpus.len(), 1);
    assert!(affinity.allowed_cpus.contains(&0));
}

#[test]
fn test_cpu_affinity_new_multiple() {
    let affinity = CpuAffinity::new(alloc::vec![0, 2, 4, 6]);
    assert_eq!(affinity.allowed_cpus.len(), 4);
    assert!(affinity.allowed_cpus.contains(&0));
    assert!(affinity.allowed_cpus.contains(&2));
    assert!(affinity.allowed_cpus.contains(&4));
    assert!(affinity.allowed_cpus.contains(&6));
}

#[test]
fn test_cpu_affinity_new_empty() {
    let affinity = CpuAffinity::new(alloc::vec![]);
    assert_eq!(affinity.allowed_cpus.len(), 0);
}

#[test]
fn test_cpu_affinity_clone() {
    let affinity1 = CpuAffinity::new(alloc::vec![1, 3, 5]);
    let affinity2 = affinity1.clone();
    assert_eq!(affinity1.allowed_cpus, affinity2.allowed_cpus);
}

#[test]
fn test_cpu_affinity_debug() {
    let affinity = CpuAffinity::new(alloc::vec![0, 1]);
    let debug_str = alloc::format!("{:?}", affinity);
    assert!(debug_str.contains("CpuAffinity"));
}

#[test]
fn test_task_with_custom_affinity() {
    let affinity = CpuAffinity::new(alloc::vec![0, 1, 2, 3]);
    let task = Task::spawn("test", dummy_task_fn, Priority::Normal, affinity);
    assert_eq!(task.affinity.allowed_cpus.len(), 4);
}
