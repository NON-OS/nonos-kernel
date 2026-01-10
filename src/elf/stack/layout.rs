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

use crate::elf::auxv::AuxEntry;

pub const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024;
pub const MIN_STACK_SIZE: usize = 64 * 1024;
pub const STACK_ALIGNMENT: usize = 16;
pub const POINTER_SIZE: usize = 8;

#[derive(Debug, Clone)]
pub struct StackLayout {
    pub stack_top: VirtAddr,
    pub stack_bottom: VirtAddr,
    pub stack_pointer: VirtAddr,
    pub argc_ptr: VirtAddr,
    pub argv_ptr: VirtAddr,
    pub envp_ptr: VirtAddr,
    pub auxv_ptr: VirtAddr,
}

impl StackLayout {
    pub fn stack_size(&self) -> usize {
        (self.stack_top.as_u64() - self.stack_bottom.as_u64()) as usize
    }

    pub fn used_size(&self) -> usize {
        (self.stack_top.as_u64() - self.stack_pointer.as_u64()) as usize
    }

    pub fn available_size(&self) -> usize {
        (self.stack_pointer.as_u64() - self.stack_bottom.as_u64()) as usize
    }
}

#[derive(Debug)]
pub struct StackConfig {
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub auxv: Vec<AuxEntry>,
    pub stack_size: usize,
}

impl StackConfig {
    pub fn new() -> Self {
        Self {
            args: Vec::new(),
            env: Vec::new(),
            auxv: Vec::new(),
            stack_size: DEFAULT_STACK_SIZE,
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

    pub fn with_auxv(mut self, auxv: Vec<AuxEntry>) -> Self {
        self.auxv = auxv;
        self
    }

    pub fn with_stack_size(mut self, size: usize) -> Self {
        self.stack_size = size.max(MIN_STACK_SIZE);
        self
    }

    pub fn add_arg(&mut self, arg: String) {
        self.args.push(arg);
    }

    pub fn add_env(&mut self, key: &str, value: &str) {
        let mut entry = String::with_capacity(key.len() + value.len() + 1);
        entry.push_str(key);
        entry.push('=');
        entry.push_str(value);
        self.env.push(entry);
    }

    pub fn argc(&self) -> usize {
        self.args.len()
    }

    pub fn strings_size(&self) -> usize {
        let args_size: usize = self.args.iter().map(|s| s.len() + 1).sum();
        let env_size: usize = self.env.iter().map(|s| s.len() + 1).sum();
        args_size + env_size
    }

    pub fn pointers_size(&self) -> usize {
        let argc_size = POINTER_SIZE;
        let argv_ptrs = (self.args.len() + 1) * POINTER_SIZE;
        let envp_ptrs = (self.env.len() + 1) * POINTER_SIZE;
        let auxv_size = self.auxv.len() * AuxEntry::SIZE;
        argc_size + argv_ptrs + envp_ptrs + auxv_size
    }

    pub fn total_setup_size(&self) -> usize {
        self.strings_size() + self.pointers_size() + STACK_ALIGNMENT
    }
}

impl Default for StackConfig {
    fn default() -> Self {
        Self::new()
    }
}
