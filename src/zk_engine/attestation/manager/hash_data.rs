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

use super::types::AttestationManager;
use crate::crypto::hash::blake3_hash;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

pub(super) fn hash_kernel_data(_mgr: &AttestationManager) -> Result<[u8; 32], ZKError> {
    let mut hasher_input = Vec::new();
    let sections = crate::memory::layout::kernel_sections();
    for section in sections.iter() {
        if section.rw && !section.rx {
            let start = section.start as *const u8;
            let size = section.size() as usize;
            let mut offset = 0;
            while offset < size {
                let chunk_size = core::cmp::min(4096, size - offset);
                let chunk_ptr = unsafe { start.add(offset) };
                let chunk = unsafe { core::slice::from_raw_parts(chunk_ptr, chunk_size) };
                hasher_input.extend_from_slice(&blake3_hash(chunk));
                offset += chunk_size;
            }
        }
    }
    let process_table = crate::process::get_process_table();
    let process_list = process_table.get_all_processes();
    hasher_input.extend_from_slice(&(process_list.len() as u64).to_le_bytes());
    for proc in process_list.iter() {
        hasher_input.extend_from_slice(&proc.pid.to_le_bytes());
        let state = *proc.state.lock();
        let state_num: u32 = match state {
            crate::process::nonos_core::ProcessState::New => 0,
            crate::process::nonos_core::ProcessState::Ready => 1,
            crate::process::nonos_core::ProcessState::Running => 2,
            crate::process::nonos_core::ProcessState::Sleeping => 3,
            crate::process::nonos_core::ProcessState::Stopped => 4,
            crate::process::nonos_core::ProcessState::Zombie(_) => 5,
            crate::process::nonos_core::ProcessState::Terminated(_) => 6,
        };
        hasher_input.extend_from_slice(&state_num.to_le_bytes());
    }
    let sched_stats = crate::sched::get_scheduler_stats();
    hasher_input.extend_from_slice(&sched_stats.context_switches.to_le_bytes());
    hasher_input.extend_from_slice(&sched_stats.tick_count.to_le_bytes());
    hasher_input.extend_from_slice(&sched_stats.wakeups.to_le_bytes());
    let mem_stats = crate::memory::get_memory_system_stats();
    hasher_input.extend_from_slice(&mem_stats.total_bytes.to_le_bytes());
    hasher_input.extend_from_slice(&mem_stats.vmalloc_total.to_le_bytes());
    hasher_input.extend_from_slice(&(mem_stats.active_allocations as u64).to_le_bytes());
    Ok(blake3_hash(&hasher_input))
}
