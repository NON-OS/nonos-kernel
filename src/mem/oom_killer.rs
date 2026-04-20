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

use crate::process::ProcessManager;
use crate::mem::vmm::VirtualMemoryManager;
use crate::logging::log_error;

pub fn trigger_oom_killer(required_pages: usize) {
    log_error("OOM: System out of memory, selecting victim process");

    let victim_pid = select_oom_victim();
    if let Some(pid) = victim_pid {
        log_error(&format!("OOM: Killing process {}", pid));
        ProcessManager::kill_process(pid, 9);
        VirtualMemoryManager::reclaim_process_memory(pid);
    } else {
        log_error("OOM: No suitable victim found, system may hang");
    }
}

fn select_oom_victim() -> Option<u64> {
    let processes = ProcessManager::get_all_processes();
    let mut best_score = 0;
    let mut victim_pid = None;

    for process in processes {
        if process.is_kernel_thread() || process.is_init() {
            continue;
        }

        let score = calculate_oom_score(&process);
        if score > best_score {
            best_score = score;
            victim_pid = Some(process.pid());
        }
    }

    victim_pid
}

fn calculate_oom_score(process: &Process) -> u64 {
    let memory_usage = process.memory_usage_mb();
    let runtime_penalty = if process.runtime_seconds() > 300 { 100 } else { 0 };
    let priority_bonus = if process.priority() < 0 { 0 } else { process.priority() as u64 * 10 };

    memory_usage + runtime_penalty - priority_bonus
}