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

use crate::memory::unified::{get_memory_system_stats, MemorySystemStats};

pub fn get_memory_stats() -> MemorySystemStats {
    get_memory_system_stats()
}

// WAVE 3 (Boundary Hardening) target: this function performs a privileged
// raw read of user memory after only a VMA range check. No copy_from_user
// fault discipline, no UAF/page-fault guard. Audit-flagged trust-boundary
// violation (DEEP_AUDIT_PASS2). Preserved verbatim during Phase 1
// consolidation; rewrite belongs to the syscall-boundary hardening pass,
// not memory consolidation.
pub fn read_process_memory(pid: u32, addr: u64, buf: &mut [u8]) -> Result<usize, i32> {
    let pcb = crate::process::PROCESS_TABLE.find_by_pid(pid).ok_or(-3)?;
    let mem = pcb.memory.lock();
    for vma in &mem.vmas {
        if addr >= vma.start.as_u64() && addr < vma.end.as_u64() {
            let max_len = (vma.end.as_u64() - addr) as usize;
            let copy_len = buf.len().min(max_len);
            unsafe {
                core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), copy_len);
            }
            return Ok(copy_len);
        }
    }
    Err(-14)
}

pub fn get_process_vm_areas(pid: u32) -> alloc::vec::Vec<(u64, u64, u32)> {
    crate::process::PROCESS_TABLE
        .find_by_pid(pid)
        .map(|pcb| {
            pcb.memory
                .lock()
                .vmas
                .iter()
                .map(|v| (v.start.as_u64(), v.end.as_u64(), v.flags.bits() as u32))
                .collect()
        })
        .unwrap_or_default()
}
