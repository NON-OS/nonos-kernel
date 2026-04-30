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

// CANONICAL: scheduler authority namespace (Phase 1 winner).
// Per CANONICAL_SUBSYSTEM_WINNER_MAP.md, scheduling belongs to process/task
// lifecycle ownership. The live dispatcher under `src/sched` is frozen and
// will be migrated here in Wave 2 (kernel core rebuild). New scheduler-domain
// code must land here, not in `src/sched`. Today this module owns the Linux
// sched_setattr/setpolicy/setaffinity/setnice policy registry consumed by the
// syscall layer; the orphan local `runqueue` is retained as a migration target
// only and is not yet wired to the live dispatcher.

extern crate alloc;

pub mod policy;
pub mod policy_types;
mod runqueue;
#[cfg(test)]
mod tests;

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
