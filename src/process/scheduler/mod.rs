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

// The scheduler corner of the process tree. The `sched_setattr` /
// `setpolicy` / `setaffinity` / `setnice` policy registry that the syscall
// layer talks to lives here, plus the PID run queue (`dispatch`) and the
// preemption atomics and tick/yield/switch logic (`preemption`) that were
// lifted out of `src/sched`. The dispatcher loop itself still lives over
// in `src/sched/scheduler/core`; the kernel core rebuild moves that too.

extern crate alloc;

pub mod dispatch;
pub mod policy;
pub mod policy_types;
pub mod preemption;
mod runqueue;
#[cfg(test)]
mod tests;

// `selection` still lives over in `src/sched/scheduler/selection`; aliased
// here so `preemption` can keep its sibling-style `super::super::selection`
// paths after the lift. The next cut moves selection too and this line
// goes away.
pub use crate::sched::scheduler::selection;

pub use policy::{
    get_affinity, get_ioprio, get_nice, get_online_cpu_count, get_online_cpu_mask, get_policy,
    get_priority, get_sched_attr, get_stats, init_process, remove_process, set_affinity,
    set_ioprio, set_nice, set_policy, set_priority, set_sched_attr,
};
pub use policy_types::{
    decode_ioprio_class, decode_ioprio_level, encode_ioprio, LinuxSchedAttr, SchedAttr, SchedParam,
    SchedPolicyStats, IOPRIO_CLASS_BE, IOPRIO_CLASS_IDLE, IOPRIO_CLASS_NONE, IOPRIO_CLASS_RT,
    IOPRIO_WHO_PGRP, IOPRIO_WHO_PROCESS, IOPRIO_WHO_USER, NICE_DEFAULT, NICE_MAX, NICE_MIN,
    SCHED_BATCH, SCHED_DEADLINE, SCHED_FIFO, SCHED_IDLE, SCHED_NORMAL, SCHED_PRIORITY_MAX,
    SCHED_PRIORITY_MIN, SCHED_RR,
};
pub use runqueue::RunQueue;
