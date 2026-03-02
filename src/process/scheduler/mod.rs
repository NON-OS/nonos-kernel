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

mod runqueue;
pub mod policy_types;
pub mod policy;
#[cfg(test)]
mod tests;

pub use runqueue::RunQueue;
pub use policy_types::{
    SchedAttr, SchedParam, LinuxSchedAttr, SchedPolicyStats,
    encode_ioprio, decode_ioprio_class, decode_ioprio_level,
    SCHED_NORMAL, SCHED_FIFO, SCHED_RR, SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE,
    SCHED_PRIORITY_MIN, SCHED_PRIORITY_MAX,
    NICE_MIN, NICE_MAX, NICE_DEFAULT,
    IOPRIO_CLASS_NONE, IOPRIO_CLASS_RT, IOPRIO_CLASS_BE, IOPRIO_CLASS_IDLE,
    IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER,
};
pub use policy::{
    get_sched_attr, set_sched_attr, get_policy, set_policy,
    get_priority, set_priority, get_nice, set_nice,
    get_affinity, set_affinity, get_ioprio, set_ioprio,
    init_process, remove_process, get_stats,
    get_online_cpu_count, get_online_cpu_mask,
};
