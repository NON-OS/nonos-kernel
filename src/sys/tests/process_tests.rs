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
use crate::test::framework::TestResult;
use core::mem;

pub(crate) fn test_max_tasks_value() -> TestResult {
    if MAX_TASKS != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_stack_size_value() -> TestResult {
    if TASK_STACK_SIZE != 64 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_stack_size_alignment() -> TestResult {
    if TASK_STACK_SIZE % 4096 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_state_empty_value() -> TestResult {
    if TaskState::Empty as u8 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_state_ready_value() -> TestResult {
    if TaskState::Ready as u8 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_state_running_value() -> TestResult {
    if TaskState::Running as u8 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_state_blocked_value() -> TestResult {
    if TaskState::Blocked as u8 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_state_sleeping_value() -> TestResult {
    if TaskState::Sleeping as u8 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_state_terminated_value() -> TestResult {
    if TaskState::Terminated as u8 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_state_equality() -> TestResult {
    if TaskState::Ready != TaskState::Ready {
        return TestResult::Fail;
    }
    if TaskState::Ready == TaskState::Running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_state_clone() -> TestResult {
    let s1 = TaskState::Running;
    let s2 = s1.clone();
    if s1 != s2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_state_copy() -> TestResult {
    let s1 = TaskState::Sleeping;
    let s2 = s1;
    if s1 != s2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_context_empty() -> TestResult {
    let ctx = CpuContext::empty();
    if ctx.rbx != 0 {
        return TestResult::Fail;
    }
    if ctx.rbp != 0 {
        return TestResult::Fail;
    }
    if ctx.r12 != 0 {
        return TestResult::Fail;
    }
    if ctx.r13 != 0 {
        return TestResult::Fail;
    }
    if ctx.r14 != 0 {
        return TestResult::Fail;
    }
    if ctx.r15 != 0 {
        return TestResult::Fail;
    }
    if ctx.rsp != 0 {
        return TestResult::Fail;
    }
    if ctx.rip != 0 {
        return TestResult::Fail;
    }
    if ctx.rflags != 0x202 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_context_rflags_default() -> TestResult {
    let ctx = CpuContext::empty();
    if ctx.rflags & 0x200 != 0x200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_context_size() -> TestResult {
    if mem::size_of::<CpuContext>() != 72 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_context_is_copy() -> TestResult {
    let ctx1 = CpuContext::empty();
    let ctx2 = ctx1;
    if ctx1.rflags != ctx2.rflags {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_context_is_clone() -> TestResult {
    let ctx1 = CpuContext::empty();
    let ctx2 = ctx1.clone();
    if ctx1.rflags != ctx2.rflags {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_empty() -> TestResult {
    let task = Task::empty();
    if task.id != 0 {
        return TestResult::Fail;
    }
    if task.state != TaskState::Empty {
        return TestResult::Fail;
    }
    if task.name_len != 0 {
        return TestResult::Fail;
    }
    if task.stack_base != 0 {
        return TestResult::Fail;
    }
    if task.stack_size != 0 {
        return TestResult::Fail;
    }
    if task.priority != 128 {
        return TestResult::Fail;
    }
    if task.sleep_until != 0 {
        return TestResult::Fail;
    }
    if task.parent_id != 0 {
        return TestResult::Fail;
    }
    if task.exit_code != 0 {
        return TestResult::Fail;
    }
    if task.run_time != 0 {
        return TestResult::Fail;
    }
    if task.last_scheduled != 0 {
        return TestResult::Fail;
    }
    if task.switch_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_set_name() -> TestResult {
    let mut task = Task::empty();
    task.set_name(b"test_task");
    if task.name_len != 9 {
        return TestResult::Fail;
    }
    if &task.name[..9] != b"test_task" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_set_name_truncates() -> TestResult {
    let mut task = Task::empty();
    let long_name = b"this_is_a_very_long_task_name_that_exceeds_31_characters_limit";
    task.set_name(long_name);
    if task.name_len != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_get_name() -> TestResult {
    let mut task = Task::empty();
    task.set_name(b"my_task");
    let name = task.get_name();
    if name != b"my_task" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_get_name_empty() -> TestResult {
    let task = Task::empty();
    let name = task.get_name();
    if name.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_is_copy() -> TestResult {
    let task1 = Task::empty();
    let task2 = task1;
    if task1.id != task2.id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_is_clone() -> TestResult {
    let task1 = Task::empty();
    let task2 = task1.clone();
    if task1.id != task2.id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_str_empty() -> TestResult {
    if state_str(TaskState::Empty) != b"empty" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_str_ready() -> TestResult {
    if state_str(TaskState::Ready) != b"ready" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_str_running() -> TestResult {
    if state_str(TaskState::Running) != b"running" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_str_blocked() -> TestResult {
    if state_str(TaskState::Blocked) != b"blocked" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_str_sleeping() -> TestResult {
    if state_str(TaskState::Sleeping) != b"sleeping" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_state_str_terminated() -> TestResult {
    if state_str(TaskState::Terminated) != b"zombie" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_round_robin() -> TestResult {
    let policy = SchedulerPolicy::RoundRobin;
    if policy as u8 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_priority() -> TestResult {
    let policy = SchedulerPolicy::Priority;
    if policy as u8 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_fair() -> TestResult {
    let policy = SchedulerPolicy::Fair;
    if policy as u8 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_from_u8_round_robin() -> TestResult {
    let policy = SchedulerPolicy::from_u8(0);
    if policy != SchedulerPolicy::RoundRobin {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_from_u8_priority() -> TestResult {
    let policy = SchedulerPolicy::from_u8(1);
    if policy != SchedulerPolicy::Priority {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_from_u8_fair() -> TestResult {
    let policy = SchedulerPolicy::from_u8(2);
    if policy != SchedulerPolicy::Fair {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_from_u8_invalid() -> TestResult {
    let policy = SchedulerPolicy::from_u8(99);
    if policy != SchedulerPolicy::RoundRobin {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_equality() -> TestResult {
    if SchedulerPolicy::Priority != SchedulerPolicy::Priority {
        return TestResult::Fail;
    }
    if SchedulerPolicy::Priority == SchedulerPolicy::Fair {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_clone() -> TestResult {
    let p1 = SchedulerPolicy::Fair;
    let p2 = p1.clone();
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_policy_copy() -> TestResult {
    let p1 = SchedulerPolicy::Priority;
    let p2 = p1;
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_stats_struct() -> TestResult {
    let stats =
        TaskStats { run_time: 1000, switch_count: 10, priority: 128, state: TaskState::Running };
    if stats.run_time != 1000 {
        return TestResult::Fail;
    }
    if stats.switch_count != 10 {
        return TestResult::Fail;
    }
    if stats.priority != 128 {
        return TestResult::Fail;
    }
    if stats.state != TaskState::Running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_stats_copy() -> TestResult {
    let stats1 =
        TaskStats { run_time: 500, switch_count: 5, priority: 64, state: TaskState::Ready };
    let stats2 = stats1;
    if stats1.run_time != stats2.run_time {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_stats_clone() -> TestResult {
    let stats1 =
        TaskStats { run_time: 750, switch_count: 7, priority: 100, state: TaskState::Sleeping };
    let stats2 = stats1.clone();
    if stats1.run_time != stats2.run_time {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_stats_struct() -> TestResult {
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
    if stats.active_tasks != 5 {
        return TestResult::Fail;
    }
    if stats.ready_tasks != 3 {
        return TestResult::Fail;
    }
    if stats.running_tasks != 1 {
        return TestResult::Fail;
    }
    if stats.sleeping_tasks != 1 {
        return TestResult::Fail;
    }
    if stats.blocked_tasks != 0 {
        return TestResult::Fail;
    }
    if stats.context_switches != 100 {
        return TestResult::Fail;
    }
    if stats.policy != SchedulerPolicy::Priority {
        return TestResult::Fail;
    }
    if stats.quantum_us != 10000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_stats_copy() -> TestResult {
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
    if stats1.active_tasks != stats2.active_tasks {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduler_stats_clone() -> TestResult {
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
    if stats1.context_switches != stats2.context_switches {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_init_returns_bool() -> TestResult {
    let result: bool = is_init();
    if !(result == true || result == false) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_current_id_returns_u32() -> TestResult {
    init();
    let id: u32 = current_id();
    if !(id < u32::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_count_returns_u32() -> TestResult {
    init();
    let count: u32 = task_count();
    if !(count >= 1) {
        return TestResult::Fail;
    }
    if !(count <= MAX_TASKS as u32) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_switch_count_returns_u64() -> TestResult {
    init();
    let count: u64 = context_switch_count();
    if !(count < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_policy_returns_policy() -> TestResult {
    init();
    let policy: SchedulerPolicy = get_policy();
    if !(policy == SchedulerPolicy::RoundRobin
        || policy == SchedulerPolicy::Priority
        || policy == SchedulerPolicy::Fair)
    {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_policy_round_robin() -> TestResult {
    init();
    set_policy(SchedulerPolicy::RoundRobin);
    if get_policy() != SchedulerPolicy::RoundRobin {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_policy_priority() -> TestResult {
    init();
    set_policy(SchedulerPolicy::Priority);
    if get_policy() != SchedulerPolicy::Priority {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_policy_fair() -> TestResult {
    init();
    set_policy(SchedulerPolicy::Fair);
    if get_policy() != SchedulerPolicy::Fair {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_time_quantum_us() -> TestResult {
    init();
    let quantum = get_time_quantum_us();
    if !(quantum > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_time_quantum_us() -> TestResult {
    init();
    set_time_quantum_us(5000);
    let quantum = get_time_quantum_us();
    if !(quantum > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_scheduler_stats_returns_struct() -> TestResult {
    init();
    let stats = get_scheduler_stats();
    if !(stats.active_tasks >= 1) {
        return TestResult::Fail;
    }
    if !(stats.running_tasks <= stats.active_tasks) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_task_info_kernel_main() -> TestResult {
    init();
    let info = get_task_info(0);
    if !info.is_some() {
        return TestResult::Fail;
    }
    if let Some((state, name)) = info {
        if state != TaskState::Running {
            return TestResult::Fail;
        }
        if name.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_task_info_invalid_id() -> TestResult {
    init();
    let info = get_task_info(999999);
    if !info.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_task_stats_kernel_main() -> TestResult {
    init();
    let stats = get_task_stats(0);
    if !stats.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_task_stats_invalid_id() -> TestResult {
    init();
    let stats = get_task_stats(999999);
    if !stats.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_task_priority_kernel_main() -> TestResult {
    init();
    let priority = get_task_priority(0);
    if !priority.is_some() {
        return TestResult::Fail;
    }
    if priority.unwrap() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_task_priority_invalid_id() -> TestResult {
    init();
    let priority = get_task_priority(999999);
    if !priority.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_for_each_task_callback() -> TestResult {
    init();
    let mut count = 0u32;
    for_each_task(|_id, _state, _name| {
        count += 1;
    });
    if !(count >= 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_for_each_task_sees_kernel_main() -> TestResult {
    init();
    let mut found_kernel_main = false;
    for_each_task(|id, state, _name| {
        if id == 0 && state == TaskState::Running {
            found_kernel_main = true;
        }
    });
    if !found_kernel_main {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_task_info_extended_kernel_main() -> TestResult {
    init();
    let info = get_task_info_extended(0);
    if !info.is_some() {
        return TestResult::Fail;
    }
    if let Some((state, name, priority, _run_time, _switch_count)) = info {
        if state != TaskState::Running {
            return TestResult::Fail;
        }
        if name.is_empty() {
            return TestResult::Fail;
        }
        if priority != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_task_info_extended_invalid_id() -> TestResult {
    init();
    let info = get_task_info_extended(999999);
    if !info.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_default_priority() -> TestResult {
    let task = Task::empty();
    if task.priority != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_context_const_empty() -> TestResult {
    const CTX: CpuContext = CpuContext::empty();
    if CTX.rflags != 0x202 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_const_empty() -> TestResult {
    const TASK: Task = Task::empty();
    if TASK.state != TaskState::Empty {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_task_states_unique() -> TestResult {
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
            if states[i] == states[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_scheduler_policies_unique() -> TestResult {
    let policies = [SchedulerPolicy::RoundRobin, SchedulerPolicy::Priority, SchedulerPolicy::Fair];
    for i in 0..policies.len() {
        for j in (i + 1)..policies.len() {
            if policies[i] == policies[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}
