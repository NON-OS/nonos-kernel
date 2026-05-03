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
use crate::process::ProcessId;
use crate::syscall::extended::rlimit::RLimitType;
use alloc::collections::BTreeMap;
use spin::Mutex;

static PROCESS_LIMITS: Mutex<BTreeMap<ProcessId, ProcessLimits>> = Mutex::new(BTreeMap::new());

#[derive(Debug, Clone)]
pub struct ProcessLimits {
    pub max_memory_mb: u64,
    pub max_cpu_time_sec: u64,
    pub max_open_files: u32,
    pub max_processes: u32,
    pub max_stack_size_kb: u64,
    pub max_core_size_mb: u64,
    pub current_memory_mb: u64,
    pub current_cpu_time_sec: u64,
    pub current_open_files: u32,
    pub current_processes: u32,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            max_cpu_time_sec: 3600,
            max_open_files: 1024,
            max_processes: 128,
            max_stack_size_kb: 8192,
            max_core_size_mb: 100,
            current_memory_mb: 0,
            current_cpu_time_sec: 0,
            current_open_files: 0,
            current_processes: 0,
        }
    }
}

pub fn check_memory_limit(pid: ProcessId, additional_mb: u64) -> bool {
    let mut limits = PROCESS_LIMITS.lock();
    let process_limits = limits.entry(pid).or_insert_with(ProcessLimits::default);

    if process_limits.current_memory_mb + additional_mb > process_limits.max_memory_mb {
        return false;
    }

    process_limits.current_memory_mb += additional_mb;
    true
}

pub fn check_file_limit(pid: ProcessId) -> bool {
    let mut limits = PROCESS_LIMITS.lock();
    let process_limits = limits.entry(pid).or_insert_with(ProcessLimits::default);

    if process_limits.current_open_files >= process_limits.max_open_files {
        return false;
    }

    process_limits.current_open_files += 1;
    true
}

pub fn check_process_limit(parent_pid: ProcessId) -> bool {
    let mut limits = PROCESS_LIMITS.lock();
    let process_limits = limits.entry(parent_pid).or_insert_with(ProcessLimits::default);

    if process_limits.current_processes >= process_limits.max_processes {
        return false;
    }

    process_limits.current_processes += 1;
    true
}

pub fn update_cpu_time(pid: ProcessId, seconds: u64) -> bool {
    let mut limits = PROCESS_LIMITS.lock();
    let process_limits = limits.entry(pid).or_insert_with(ProcessLimits::default);

    process_limits.current_cpu_time_sec += seconds;

    if process_limits.current_cpu_time_sec > process_limits.max_cpu_time_sec {
        return false;
    }

    true
}

pub fn set_limit(pid: ProcessId, limit_type: RLimitType, soft: u64, hard: u64) {
    let mut limits = PROCESS_LIMITS.lock();
    let process_limits = limits.entry(pid).or_insert_with(ProcessLimits::default);

    match limit_type {
        RLimitType::As => process_limits.max_memory_mb = soft / (1024 * 1024),
        RLimitType::Core => process_limits.max_core_size_mb = soft / (1024 * 1024),
        RLimitType::Cpu => process_limits.max_cpu_time_sec = soft,
        RLimitType::Nofile => process_limits.max_open_files = soft as u32,
        RLimitType::Nproc => process_limits.max_processes = soft as u32,
        RLimitType::Stack => process_limits.max_stack_size_kb = soft / 1024,
        _ => {}
    }
}

pub fn release_resources(pid: ProcessId) {
    let mut limits = PROCESS_LIMITS.lock();
    limits.remove(&pid);
}

pub fn get_current_usage(pid: ProcessId) -> Option<ProcessLimits> {
    let limits = PROCESS_LIMITS.lock();
    limits.get(&pid).cloned()
}
