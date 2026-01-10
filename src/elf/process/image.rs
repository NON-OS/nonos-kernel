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

use alloc::string::String;
use alloc::vec::Vec;
use x86_64::VirtAddr;

use crate::elf::loader::ElfImage;
use crate::elf::stack::StackLayout;
use crate::elf::tls::TlsInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    Ready,
    Running,
    Blocked,
    Terminated,
}

#[derive(Debug)]
pub struct ProcessImage {
    pub executable: ElfImage,
    pub interpreter: Option<ElfImage>,
    pub stack: StackLayout,
    pub entry_point: VirtAddr,
    pub initial_sp: VirtAddr,
    pub brk_start: VirtAddr,
    pub brk_current: VirtAddr,
    pub tls: Option<TlsInfo>,
    pub state: ProcessState,
}

impl ProcessImage {
    pub fn new(
        executable: ElfImage,
        interpreter: Option<ElfImage>,
        stack: StackLayout,
    ) -> Self {
        let entry_point = interpreter
            .as_ref()
            .map(|i| i.entry_point)
            .unwrap_or(executable.entry_point);

        let brk_start = Self::calculate_brk(&executable);

        Self {
            executable,
            interpreter,
            entry_point,
            initial_sp: stack.stack_pointer,
            brk_start,
            brk_current: brk_start,
            tls: None,
            state: ProcessState::Created,
            stack,
        }
    }

    fn calculate_brk(image: &ElfImage) -> VirtAddr {
        let mut highest = image.base_addr.as_u64();
        for segment in &image.segments {
            let end = segment.vaddr.as_u64() + segment.size as u64;
            if end > highest {
                highest = end;
            }
        }
        let aligned = (highest + 0xFFF) & !0xFFF;
        VirtAddr::new(aligned)
    }

    pub fn set_tls(&mut self, tls: TlsInfo) {
        self.tls = Some(tls);
    }

    pub fn has_interpreter(&self) -> bool {
        self.interpreter.is_some()
    }

    pub fn has_tls(&self) -> bool {
        self.tls.is_some()
    }

    pub fn total_memory_size(&self) -> usize {
        let exe_size = self.executable.size;
        let interp_size = self.interpreter.as_ref().map(|i| i.size).unwrap_or(0);
        let stack_size = self.stack.stack_size();
        exe_size + interp_size + stack_size
    }

    pub fn set_ready(&mut self) {
        self.state = ProcessState::Ready;
    }

    pub fn set_running(&mut self) {
        self.state = ProcessState::Running;
    }

    pub fn set_blocked(&mut self) {
        self.state = ProcessState::Blocked;
    }

    pub fn set_terminated(&mut self) {
        self.state = ProcessState::Terminated;
    }

    pub fn is_ready(&self) -> bool {
        self.state == ProcessState::Ready
    }

    pub fn is_running(&self) -> bool {
        self.state == ProcessState::Running
    }

    pub fn is_terminated(&self) -> bool {
        self.state == ProcessState::Terminated
    }

    pub fn extend_brk(&mut self, increment: usize) -> Option<VirtAddr> {
        let new_brk = self.brk_current.as_u64().checked_add(increment as u64)?;
        self.brk_current = VirtAddr::new(new_brk);
        Some(self.brk_current)
    }
}

#[derive(Debug)]
pub struct ProcessConfig {
    pub name: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub stack_size: usize,
    pub uid: u32,
    pub gid: u32,
}

impl ProcessConfig {
    pub fn new(name: String) -> Self {
        Self {
            name,
            args: Vec::new(),
            env: Vec::new(),
            stack_size: crate::elf::stack::DEFAULT_STACK_SIZE,
            uid: 0,
            gid: 0,
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_env(mut self, env: Vec<String>) -> Self {
        self.env = env;
        self
    }

    pub fn with_stack_size(mut self, size: usize) -> Self {
        self.stack_size = size;
        self
    }

    pub fn with_credentials(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self::new(String::new())
    }
}
