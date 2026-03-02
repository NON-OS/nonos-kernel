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

pub const SCHED_NORMAL: i32 = 0;
pub const SCHED_FIFO: i32 = 1;
pub const SCHED_RR: i32 = 2;
pub const SCHED_BATCH: i32 = 3;
pub const SCHED_IDLE: i32 = 5;
pub const SCHED_DEADLINE: i32 = 6;

pub const SCHED_PRIORITY_MIN: i32 = 1;
pub const SCHED_PRIORITY_MAX: i32 = 99;

pub const NICE_MIN: i32 = -20;
pub const NICE_MAX: i32 = 19;
pub const NICE_DEFAULT: i32 = 0;

pub const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
pub const SCHED_FLAG_RECLAIM: u64 = 0x02;
pub const SCHED_FLAG_DL_OVERRUN: u64 = 0x04;
pub const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
pub const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
pub const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
pub const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;

pub const IOPRIO_CLASS_NONE: i32 = 0;
pub const IOPRIO_CLASS_RT: i32 = 1;
pub const IOPRIO_CLASS_BE: i32 = 2;
pub const IOPRIO_CLASS_IDLE: i32 = 3;

pub const IOPRIO_WHO_PROCESS: i32 = 1;
pub const IOPRIO_WHO_PGRP: i32 = 2;
pub const IOPRIO_WHO_USER: i32 = 3;

pub const DEFAULT_TIMESLICE_MS: u32 = 100;
pub const FIFO_TIMESLICE_MS: u32 = 0;
pub const RR_TIMESLICE_MS: u32 = 100;

#[derive(Debug, Clone)]
pub struct SchedAttr {
    pub policy: i32,
    pub rt_priority: i32,
    pub nice: i32,
    pub cpu_affinity: u64,
    pub ioprio: u16,
    pub flags: u64,
    pub timeslice: u32,
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
}

impl Default for SchedAttr {
    fn default() -> Self {
        Self {
            policy: SCHED_NORMAL,
            rt_priority: 0,
            nice: NICE_DEFAULT,
            cpu_affinity: 0xFFFF_FFFF_FFFF_FFFF,
            ioprio: encode_ioprio(IOPRIO_CLASS_BE, 4),
            flags: 0,
            timeslice: DEFAULT_TIMESLICE_MS,
            runtime: 0,
            deadline: 0,
            period: 0,
        }
    }
}

impl SchedAttr {
    pub fn is_realtime(&self) -> bool {
        self.policy == SCHED_FIFO || self.policy == SCHED_RR
    }

    pub fn effective_priority(&self) -> i32 {
        match self.policy {
            SCHED_FIFO | SCHED_RR => 100 + self.rt_priority,
            SCHED_DEADLINE => 200,
            SCHED_IDLE => -1,
            SCHED_BATCH => 19 - self.nice,
            _ => 20 - self.nice,
        }
    }

    pub fn can_run_on_cpu(&self, cpu: u32) -> bool {
        if cpu >= 64 {
            return false;
        }
        (self.cpu_affinity & (1u64 << cpu)) != 0
    }

    pub fn get_timeslice(&self) -> u32 {
        match self.policy {
            SCHED_FIFO => FIFO_TIMESLICE_MS,
            SCHED_RR => RR_TIMESLICE_MS,
            _ => self.timeslice,
        }
    }
}

pub fn encode_ioprio(class: i32, level: i32) -> u16 {
    ((class as u16 & 0x7) << 13) | (level as u16 & 0x1FFF)
}

pub fn decode_ioprio_class(ioprio: u16) -> i32 {
    ((ioprio >> 13) & 0x7) as i32
}

pub fn decode_ioprio_level(ioprio: u16) -> i32 {
    (ioprio & 0x1FFF) as i32
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedParam {
    pub sched_priority: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LinuxSchedAttr {
    pub size: u32,
    pub sched_policy: u32,
    pub sched_flags: u64,
    pub sched_nice: i32,
    pub sched_priority: i32,
    pub sched_runtime: u64,
    pub sched_deadline: u64,
    pub sched_period: u64,
    pub sched_util_min: u32,
    pub sched_util_max: u32,
}

impl Default for LinuxSchedAttr {
    fn default() -> Self {
        Self {
            size: core::mem::size_of::<LinuxSchedAttr>() as u32,
            sched_policy: SCHED_NORMAL as u32,
            sched_flags: 0,
            sched_nice: 0,
            sched_priority: 0,
            sched_runtime: 0,
            sched_deadline: 0,
            sched_period: 0,
            sched_util_min: 0,
            sched_util_max: 1024,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SchedPolicyStats {
    pub total_processes: u32,
    pub normal_count: u32,
    pub fifo_count: u32,
    pub rr_count: u32,
    pub batch_count: u32,
    pub idle_count: u32,
    pub deadline_count: u32,
    pub policy_changes: u64,
    pub affinity_changes: u64,
    pub priority_changes: u64,
}
