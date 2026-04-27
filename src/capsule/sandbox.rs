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
use super::types::CapsuleId;
use crate::memory::virtual_memory::AddressSpace;
use alloc::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    UnauthorizedCap,
    MemoryExceeded,
    CpuExceeded,
    MemoryAccess,
    IllegalSyscall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxState {
    Ready,
    Running,
    Blocked,
    Exited(i32),
    Violated(Violation),
}

pub struct Sandbox {
    pub capsule_id: CapsuleId,
    addr_space: Arc<AddressSpace>,
    entry: u64,
    caps: u64,
    mem_limit: u64,
    mem_used: u64,
    state: SandboxState,
}

impl Sandbox {
    pub fn new(id: CapsuleId, as_: AddressSpace, entry: u64, caps: u64, mem_limit: u64) -> Self {
        Self {
            capsule_id: id,
            addr_space: Arc::new(as_),
            entry,
            caps,
            mem_limit,
            mem_used: 0,
            state: SandboxState::Ready,
        }
    }

    pub fn new_minimal(id: CapsuleId, entry: u64, caps: u64, mem_limit: u64) -> Self {
        use x86_64::{PhysAddr, VirtAddr};
        let addr_space = AddressSpace {
            asid: id as u32,
            page_table: PhysAddr::new(0),
            vm_areas: alloc::vec::Vec::new(),
            heap_start: VirtAddr::new(0),
            heap_end: VirtAddr::new(0),
            stack_start: VirtAddr::new(0),
            stack_end: VirtAddr::new(0),
            mmap_start: VirtAddr::new(0),
            creation_time: crate::time::unix_timestamp(),
        };
        Self {
            capsule_id: id,
            addr_space: Arc::new(addr_space),
            entry,
            caps,
            mem_limit,
            mem_used: 0,
            state: SandboxState::Ready,
        }
    }

    pub fn has_cap(&self, cap: u64) -> bool {
        self.caps & cap != 0
    }

    pub fn use_cap(&mut self, cap: u64) -> Result<(), Violation> {
        if self.caps & cap == 0 {
            self.state = SandboxState::Violated(Violation::UnauthorizedCap);
            return Err(Violation::UnauthorizedCap);
        }
        Ok(())
    }

    pub fn alloc_mem(&mut self, size: u64) -> Result<(), Violation> {
        if self.mem_used + size > self.mem_limit {
            self.state = SandboxState::Violated(Violation::MemoryExceeded);
            return Err(Violation::MemoryExceeded);
        }
        self.mem_used += size;
        Ok(())
    }

    pub fn free_mem(&mut self, size: u64) {
        self.mem_used = self.mem_used.saturating_sub(size);
    }
    pub fn state(&self) -> SandboxState {
        self.state
    }
    pub fn set_state(&mut self, s: SandboxState) {
        self.state = s;
    }
    pub fn addr_space(&self) -> Arc<AddressSpace> {
        self.addr_space.clone()
    }
    pub fn terminate(&mut self, code: i32) {
        self.state = SandboxState::Exited(code);
    }
    pub fn caps(&self) -> u64 {
        self.caps
    }
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn mem_used(&self) -> u64 {
        self.mem_used
    }
    pub fn mem_limit(&self) -> u64 {
        self.mem_limit
    }
}
