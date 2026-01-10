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

use alloc::vec::Vec;
use core::ptr;
use x86_64::VirtAddr;

use super::layout::{StackConfig, StackLayout, POINTER_SIZE, STACK_ALIGNMENT};
use crate::elf::auxv::AuxEntry;
use crate::elf::errors::{ElfError, ElfResult};

pub struct StackSetup {
    stack_top: VirtAddr,
    stack_bottom: VirtAddr,
    current: VirtAddr,
}

impl StackSetup {
    pub fn new(stack_top: VirtAddr, stack_size: usize) -> Self {
        let stack_bottom = VirtAddr::new(stack_top.as_u64() - stack_size as u64);
        Self {
            stack_top,
            stack_bottom,
            current: stack_top,
        }
    }

    pub fn setup(&mut self, config: &StackConfig) -> ElfResult<StackLayout> {
        if config.total_setup_size() > self.available_space() {
            return Err(ElfError::MemoryAllocationFailed);
        }

        let string_ptrs = self.write_strings(config)?;
        let (argv_ptr, envp_ptr, auxv_ptr) = self.write_pointers(config, &string_ptrs)?;
        let argc_ptr = self.write_argc(config.argc())?;

        self.align_stack();

        Ok(StackLayout {
            stack_top: self.stack_top,
            stack_bottom: self.stack_bottom,
            stack_pointer: self.current,
            argc_ptr,
            argv_ptr,
            envp_ptr,
            auxv_ptr,
        })
    }

    fn write_strings(&mut self, config: &StackConfig) -> ElfResult<(Vec<VirtAddr>, Vec<VirtAddr>)> {
        let mut argv_ptrs = Vec::with_capacity(config.args.len());
        let mut envp_ptrs = Vec::with_capacity(config.env.len());

        for arg in &config.args {
            let ptr = self.push_string(arg)?;
            argv_ptrs.push(ptr);
        }

        for env in &config.env {
            let ptr = self.push_string(env)?;
            envp_ptrs.push(ptr);
        }

        Ok((argv_ptrs, envp_ptrs))
    }

    fn write_pointers(
        &mut self,
        config: &StackConfig,
        string_ptrs: &(Vec<VirtAddr>, Vec<VirtAddr>),
    ) -> ElfResult<(VirtAddr, VirtAddr, VirtAddr)> {
        let (argv_ptrs, envp_ptrs) = string_ptrs;

        self.align_to(POINTER_SIZE);

        let auxv_ptr = self.push_auxv(&config.auxv)?;
        let envp_ptr = self.push_pointer_array(envp_ptrs)?;
        let argv_ptr = self.push_pointer_array(argv_ptrs)?;

        Ok((argv_ptr, envp_ptr, auxv_ptr))
    }

    fn write_argc(&mut self, argc: usize) -> ElfResult<VirtAddr> {
        self.push_u64(argc as u64)
    }

    fn push_string(&mut self, s: &str) -> ElfResult<VirtAddr> {
        let bytes = s.as_bytes();
        let len = bytes.len() + 1;

        if len > self.available_space() {
            return Err(ElfError::MemoryAllocationFailed);
        }

        self.current = VirtAddr::new(self.current.as_u64() - len as u64);

        // SAFETY: Stack memory is valid and writable
        unsafe {
            let dst = self.current.as_mut_ptr::<u8>();
            ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
            ptr::write(dst.add(bytes.len()), 0);
        }

        Ok(self.current)
    }

    fn push_u64(&mut self, value: u64) -> ElfResult<VirtAddr> {
        if POINTER_SIZE > self.available_space() {
            return Err(ElfError::MemoryAllocationFailed);
        }

        self.current = VirtAddr::new(self.current.as_u64() - POINTER_SIZE as u64);

        // SAFETY: Stack memory is valid and aligned
        unsafe {
            ptr::write(self.current.as_mut_ptr::<u64>(), value);
        }

        Ok(self.current)
    }

    fn push_pointer_array(&mut self, ptrs: &[VirtAddr]) -> ElfResult<VirtAddr> {
        self.push_u64(0)?;

        for ptr in ptrs.iter().rev() {
            self.push_u64(ptr.as_u64())?;
        }

        Ok(self.current)
    }

    fn push_auxv(&mut self, auxv: &[AuxEntry]) -> ElfResult<VirtAddr> {
        for entry in auxv.iter().rev() {
            self.push_u64(entry.a_val)?;
            self.push_u64(entry.a_type)?;
        }

        Ok(self.current)
    }

    fn align_to(&mut self, alignment: usize) {
        let addr = self.current.as_u64();
        let aligned = addr & !(alignment as u64 - 1);
        self.current = VirtAddr::new(aligned);
    }

    fn align_stack(&mut self) {
        self.align_to(STACK_ALIGNMENT);
    }

    fn available_space(&self) -> usize {
        (self.current.as_u64() - self.stack_bottom.as_u64()) as usize
    }
}

pub fn setup_user_stack(
    stack_top: VirtAddr,
    stack_size: usize,
    config: &StackConfig,
) -> ElfResult<StackLayout> {
    let mut setup = StackSetup::new(stack_top, stack_size);
    setup.setup(config)
}
