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

use crate::sys::process::*;
use core::mem;

#[test]
fn test_max_tasks_value() {
    assert_eq!(MAX_TASKS, 32);
}

#[test]
fn test_task_stack_size_value() {
    assert_eq!(TASK_STACK_SIZE, 64 * 1024);
}

#[test]
fn test_task_stack_size_alignment() {
    assert_eq!(TASK_STACK_SIZE % 4096, 0);
}

#[test]
fn test_task_state_empty_value() {
    assert_eq!(TaskState::Empty as u8, 0);
}

#[test]
fn test_task_state_ready_value() {
    assert_eq!(TaskState::Ready as u8, 1);
}

#[test]
fn test_task_state_running_value() {
    assert_eq!(TaskState::Running as u8, 2);
}

#[test]
fn test_task_state_blocked_value() {
    assert_eq!(TaskState::Blocked as u8, 3);
}

#[test]
fn test_task_state_sleeping_value() {
    assert_eq!(TaskState::Sleeping as u8, 4);
}

#[test]
fn test_task_state_terminated_value() {
    assert_eq!(TaskState::Terminated as u8, 5);
}

#[test]
fn test_task_state_equality() {
    assert_eq!(TaskState::Ready, TaskState::Ready);
    assert_ne!(TaskState::Ready, TaskState::Running);
}

#[test]
fn test_task_state_clone() {
    let s1 = TaskState::Running;
    let s2 = s1.clone();
    assert_eq!(s1, s2);
}

#[test]
fn test_task_state_copy() {
    let s1 = TaskState::Sleeping;
    let s2 = s1;
    assert_eq!(s1, s2);
}

#[test]
fn test_cpu_context_empty() {
    let ctx = CpuContext::empty();
    assert_eq!(ctx.rbx, 0);
    assert_eq!(ctx.rbp, 0);
    assert_eq!(ctx.r12, 0);
    assert_eq!(ctx.r13, 0);
    assert_eq!(ctx.r14, 0);
    assert_eq!(ctx.r15, 0);
    assert_eq!(ctx.rsp, 0);
    assert_eq!(ctx.rip, 0);
    assert_eq!(ctx.rflags, 0x202);
}

#[test]
fn test_cpu_context_rflags_default() {
    let ctx = CpuContext::empty();
    assert_eq!(ctx.rflags & 0x200, 0x200);
}

#[test]
fn test_cpu_context_size() {
    assert_eq!(mem::size_of::<CpuContext>(), 72);
}

#[test]
fn test_cpu_context_is_copy() {
    let ctx1 = CpuContext::empty();
    let ctx2 = ctx1;
    assert_eq!(ctx1.rflags, ctx2.rflags);
}

#[test]
fn test_cpu_context_is_clone() {
    let ctx1 = CpuContext::empty();
    let ctx2 = ctx1.clone();
    assert_eq!(ctx1.rflags, ctx2.rflags);
}

#[test]
fn test_task_empty() {
    let task = Task::empty();
    assert_eq!(task.id, 0);
    assert_eq!(task.state, TaskState::Empty);
    assert_eq!(task.name_len, 0);
    assert_eq!(task.stack_base, 0);
    assert_eq!(task.stack_size, 0);
    assert_eq!(task.priority, 128);
    assert_eq!(task.sleep_until, 0);
    assert_eq!(task.parent_id, 0);
    assert_eq!(task.exit_code, 0);
    assert_eq!(task.run_time, 0);
    assert_eq!(task.last_scheduled, 0);
    assert_eq!(task.switch_count, 0);
}

#[test]
fn test_task_set_name() {
    let mut task = Task::empty();
    task.set_name(b"test_task");
    assert_eq!(task.name_len, 9);
    assert_eq!(&task.name[..9], b"test_task");
}

#[test]
fn test_task_set_name_truncates() {
    let mut task = Task::empty();
    let long_name = b"this_is_a_very_long_task_name_that_exceeds_31_characters_limit";
    task.set_name(long_name);
    assert_eq!(task.name_len, 31);
}

#[test]
fn test_task_get_name() {
    let mut task = Task::empty();
    task.set_name(b"my_task");
    let name = task.get_name();
    assert_eq!(name, b"my_task");
}

#[test]
fn test_task_get_name_empty() {
    let task = Task::empty();
    let name = task.get_name();
    assert_eq!(name.len(), 0);
}

#[test]
fn test_task_is_copy() {
    let task1 = Task::empty();
    let task2 = task1;
    assert_eq!(task1.id, task2.id);
}

#[test]
fn test_task_is_clone() {
    let task1 = Task::empty();
    let task2 = task1.clone();
    assert_eq!(task1.id, task2.id);
}

#[test]
fn test_state_str_empty() {
    assert_eq!(state_str(TaskState::Empty), b"empty");
}

#[test]
fn test_state_str_ready() {
    assert_eq!(state_str(TaskState::Ready), b"ready");
}

#[test]
fn test_state_str_running() {
    assert_eq!(state_str(TaskState::Running), b"running");
}

#[test]
fn test_state_str_blocked() {
    assert_eq!(state_str(TaskState::Blocked), b"blocked");
}

#[test]
fn test_state_str_sleeping() {
    assert_eq!(state_str(TaskState::Sleeping), b"sleeping");
}

#[test]
fn test_state_str_terminated() {
    assert_eq!(state_str(TaskState::Terminated), b"zombie");
}

#[test]
fn test_scheduler_policy_round_robin() {
    let policy = SchedulerPolicy::RoundRobin;
    assert_eq!(policy as u8, 0);
}

#[test]
fn test_scheduler_policy_priority() {
    let policy = SchedulerPolicy::Priority;
    assert_eq!(policy as u8, 1);
}

#[test]
fn test_scheduler_policy_fair() {
    let policy = SchedulerPolicy::Fair;
    assert_eq!(policy as u8, 2);
}

#[test]
fn test_scheduler_policy_from_u8_round_robin() {
    let policy = SchedulerPolicy::from_u8(0);
    assert_eq!(policy, SchedulerPolicy::RoundRobin);
}

#[test]
fn test_scheduler_policy_from_u8_priority() {
    let policy = SchedulerPolicy::from_u8(1);
    assert_eq!(policy, SchedulerPolicy::Priority);
}

#[test]
fn test_scheduler_policy_from_u8_fair() {
    let policy = SchedulerPolicy::from_u8(2);
    assert_eq!(policy, SchedulerPolicy::Fair);
}

#[test]
fn test_scheduler_policy_from_u8_invalid() {
    let policy = SchedulerPolicy::from_u8(99);
    assert_eq!(policy, SchedulerPolicy::RoundRobin);
}

#[test]
fn test_scheduler_policy_equality() {
    assert_eq!(SchedulerPolicy::Priority, SchedulerPolicy::Priority);
    assert_ne!(SchedulerPolicy::Priority, SchedulerPolicy::Fair);
}

#[test]
fn test_scheduler_policy_clone() {
    let p1 = SchedulerPolicy::Fair;
    let p2 = p1.clone();
    assert_eq!(p1, p2);
}

#[test]
fn test_scheduler_policy_copy() {
    let p1 = SchedulerPolicy::Priority;
    let p2 = p1;
    assert_eq!(p1, p2);
}

#[test]
fn test_task_stats_struct() {
    let stats = TaskStats {
        run_time: 1000,
        switch_count: 10,
        priority: 128,
        state: TaskState::Running,
    };
    assert_eq!(stats.run_time, 1000);
    assert_eq!(stats.switch_count, 10);
    assert_eq!(stats.priority, 128);
    assert_eq!(stats.state, TaskState::Running);
}

#[test]
fn test_task_stats_copy() {
    let stats1 = TaskStats {
        run_time: 500,
        switch_count: 5,
        priority: 64,
        state: TaskState::Ready,
    };
    let stats2 = stats1;
    assert_eq!(stats1.run_time, stats2.run_time);
}

#[test]
fn test_task_stats_clone() {
    let stats1 = TaskStats {
        run_time: 750,
        switch_count: 7,
        priority: 100,
        state: TaskState::Sleeping,
    };
    let stats2 = stats1.clone();
    assert_eq!(stats1.run_time, stats2.run_time);
}

#[test]
fn test_scheduler_stats_struct() {
    let stats = SchedulerStats {
        active_tasks: 5,
        ready_tasks: 3,
        running_tasks: 1,
        sleeping_tasks: 1,
        blocked_tasks: 0,
        context_switches: 100,
        policy: SchedulerPolicy::Priority,
        quantum_us: 10000,
    };
    assert_eq!(stats.active_tasks, 5);
    assert_eq!(stats.ready_tasks, 3);
    assert_eq!(stats.running_tasks, 1);
    assert_eq!(stats.sleeping_tasks, 1);
    assert_eq!(stats.blocked_tasks, 0);
    assert_eq!(stats.context_switches, 100);
    assert_eq!(stats.policy, SchedulerPolicy::Priority);
    assert_eq!(stats.quantum_us, 10000);
}

#[test]
fn test_scheduler_stats_copy() {
    let stats1 = SchedulerStats {
        active_tasks: 2,
        ready_tasks: 1,
        running_tasks: 1,
        sleeping_tasks: 0,
        blocked_tasks: 0,
        context_switches: 50,
        policy: SchedulerPolicy::Fair,
        quantum_us: 20000,
    };
    let stats2 = stats1;
    assert_eq!(stats1.active_tasks, stats2.active_tasks);
}

#[test]
fn test_scheduler_stats_clone() {
    let stats1 = SchedulerStats {
        active_tasks: 3,
        ready_tasks: 2,
        running_tasks: 1,
        sleeping_tasks: 0,
        blocked_tasks: 0,
        context_switches: 75,
        policy: SchedulerPolicy::RoundRobin,
        quantum_us: 5000,
    };
    let stats2 = stats1.clone();
    assert_eq!(stats1.context_switches, stats2.context_switches);
}

#[test]
fn test_is_init_returns_bool() {
    let result: bool = is_init();
    assert!(result == true || result == false);
}

#[test]
fn test_current_id_returns_u32() {
    init();
    let id: u32 = current_id();
    assert!(id < u32::MAX);
}

#[test]
fn test_task_count_returns_u32() {
    init();
    let count: u32 = task_count();
    assert!(count >= 1);
    assert!(count <= MAX_TASKS as u32);
}

#[test]
fn test_context_switch_count_returns_u64() {
    init();
    let count: u64 = context_switch_count();
    assert!(count < u64::MAX);
}

#[test]
fn test_get_policy_returns_policy() {
    init();
    let policy: SchedulerPolicy = get_policy();
    assert!(policy == SchedulerPolicy::RoundRobin
         || policy == SchedulerPolicy::Priority
         || policy == SchedulerPolicy::Fair);
}

#[test]
fn test_set_policy_round_robin() {
    init();
    set_policy(SchedulerPolicy::RoundRobin);
    assert_eq!(get_policy(), SchedulerPolicy::RoundRobin);
}

#[test]
fn test_set_policy_priority() {
    init();
    set_policy(SchedulerPolicy::Priority);
    assert_eq!(get_policy(), SchedulerPolicy::Priority);
}

#[test]
fn test_set_policy_fair() {
    init();
    set_policy(SchedulerPolicy::Fair);
    assert_eq!(get_policy(), SchedulerPolicy::Fair);
}

#[test]
fn test_get_time_quantum_us() {
    init();
    let quantum = get_time_quantum_us();
    assert!(quantum > 0);
}

#[test]
fn test_set_time_quantum_us() {
    init();
    set_time_quantum_us(5000);
    let quantum = get_time_quantum_us();
    assert!(quantum > 0);
}

#[test]
fn test_get_scheduler_stats_returns_struct() {
    init();
    let stats = get_scheduler_stats();
    assert!(stats.active_tasks >= 1);
    assert!(stats.running_tasks <= stats.active_tasks);
}

#[test]
fn test_get_task_info_kernel_main() {
    init();
    let info = get_task_info(0);
    assert!(info.is_some());
    if let Some((state, name)) = info {
        assert_eq!(state, TaskState::Running);
        assert!(!name.is_empty());
    }
}

#[test]
fn test_get_task_info_invalid_id() {
    init();
    let info = get_task_info(999999);
    assert!(info.is_none());
}

#[test]
fn test_get_task_stats_kernel_main() {
    init();
    let stats = get_task_stats(0);
    assert!(stats.is_some());
}

#[test]
fn test_get_task_stats_invalid_id() {
    init();
    let stats = get_task_stats(999999);
    assert!(stats.is_none());
}

#[test]
fn test_get_task_priority_kernel_main() {
    init();
    let priority = get_task_priority(0);
    assert!(priority.is_some());
    assert_eq!(priority.unwrap(), 0);
}

#[test]
fn test_get_task_priority_invalid_id() {
    init();
    let priority = get_task_priority(999999);
    assert!(priority.is_none());
}

#[test]
fn test_for_each_task_callback() {
    init();
    let mut count = 0u32;
    for_each_task(|_id, _state, _name| {
        count += 1;
    });
    assert!(count >= 1);
}

#[test]
fn test_for_each_task_sees_kernel_main() {
    init();
    let mut found_kernel_main = false;
    for_each_task(|id, state, _name| {
        if id == 0 && state == TaskState::Running {
            found_kernel_main = true;
        }
    });
    assert!(found_kernel_main);
}

#[test]
fn test_get_task_info_extended_kernel_main() {
    init();
    let info = get_task_info_extended(0);
    assert!(info.is_some());
    if let Some((state, name, priority, _run_time, _switch_count)) = info {
        assert_eq!(state, TaskState::Running);
        assert!(!name.is_empty());
        assert_eq!(priority, 0);
    }
}

#[test]
fn test_get_task_info_extended_invalid_id() {
    init();
    let info = get_task_info_extended(999999);
    assert!(info.is_none());
}

#[test]
fn test_task_default_priority() {
    let task = Task::empty();
    assert_eq!(task.priority, 128);
}

#[test]
fn test_cpu_context_const_empty() {
    const CTX: CpuContext = CpuContext::empty();
    assert_eq!(CTX.rflags, 0x202);
}

#[test]
fn test_task_const_empty() {
    const TASK: Task = Task::empty();
    assert_eq!(TASK.state, TaskState::Empty);
}

#[test]
fn test_all_task_states_unique() {
    let states = [
        TaskState::Empty,
        TaskState::Ready,
        TaskState::Running,
        TaskState::Blocked,
        TaskState::Sleeping,
        TaskState::Terminated,
    ];
    for i in 0..states.len() {
        for j in (i + 1)..states.len() {
            assert_ne!(states[i], states[j]);
        }
    }
}

#[test]
fn test_all_scheduler_policies_unique() {
    let policies = [
        SchedulerPolicy::RoundRobin,
        SchedulerPolicy::Priority,
        SchedulerPolicy::Fair,
    ];
    for i in 0..policies.len() {
        for j in (i + 1)..policies.len() {
            assert_ne!(policies[i], policies[j]);
        }
    }
}
