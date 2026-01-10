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

use core::ptr;
use x86_64::VirtAddr;

use crate::elf::errors::{ElfError, ElfResult};

pub type InitFn = unsafe extern "C" fn();
pub type InitFnWithArgs =
    unsafe extern "C" fn(argc: i32, argv: *const *const u8, envp: *const *const u8);

pub const INIT_FN_SIZE: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct InitArrayInfo {
    pub addr: VirtAddr,
    pub size: usize,
}

impl InitArrayInfo {
    pub fn new(addr: VirtAddr, size: usize) -> Self {
        Self { addr, size }
    }

    pub fn count(&self) -> usize {
        self.size / INIT_FN_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PreInitArrayInfo {
    pub addr: VirtAddr,
    pub size: usize,
}

impl PreInitArrayInfo {
    pub fn new(addr: VirtAddr, size: usize) -> Self {
        Self { addr, size }
    }

    pub fn count(&self) -> usize {
        self.size / INIT_FN_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

pub struct InitArrayRunner {
    preinit_array: Option<PreInitArrayInfo>,
    init_fn: Option<VirtAddr>,
    init_array: Option<InitArrayInfo>,
}

impl InitArrayRunner {
    pub fn new() -> Self {
        Self { preinit_array: None, init_fn: None, init_array: None }
    }

    pub fn with_preinit_array(mut self, info: PreInitArrayInfo) -> Self {
        self.preinit_array = Some(info);
        self
    }

    pub fn with_init_fn(mut self, addr: VirtAddr) -> Self {
        self.init_fn = Some(addr);
        self
    }

    pub fn with_init_array(mut self, info: InitArrayInfo) -> Self {
        self.init_array = Some(info);
        self
    }

    pub fn run_all(&self) -> ElfResult<usize> {
        let mut count = 0;

        count += self.run_preinit_array()?;
        count += self.run_init_fn()?;
        count += self.run_init_array()?;

        Ok(count)
    }

    pub fn run_preinit_array(&self) -> ElfResult<usize> {
        let Some(ref info) = self.preinit_array else {
            return Ok(0);
        };

        if info.is_empty() {
            return Ok(0);
        }

        let count = info.count();

        for i in 0..count {
            let fn_ptr_addr = info.addr.as_u64() + (i * INIT_FN_SIZE) as u64;

            // SAFETY: Caller ensures preinit array is valid and functions are callable
            unsafe {
                let fn_ptr = ptr::read(fn_ptr_addr as *const u64);
                if fn_ptr != 0 && fn_ptr != u64::MAX {
                    let init_fn: InitFn = core::mem::transmute(fn_ptr);
                    init_fn();
                }
            }
        }

        Ok(count)
    }

    pub fn run_init_fn(&self) -> ElfResult<usize> {
        let Some(addr) = self.init_fn else {
            return Ok(0);
        };

        if addr.as_u64() == 0 {
            return Ok(0);
        }

        // SAFETY: Caller ensures init function is valid and callable
        unsafe {
            let init_fn: InitFn = core::mem::transmute(addr.as_u64());
            init_fn();
        }

        Ok(1)
    }

    pub fn run_init_array(&self) -> ElfResult<usize> {
        let Some(ref info) = self.init_array else {
            return Ok(0);
        };

        if info.is_empty() {
            return Ok(0);
        }

        let count = info.count();

        for i in 0..count {
            let fn_ptr_addr = info.addr.as_u64() + (i * INIT_FN_SIZE) as u64;

            // SAFETY: Caller ensures init array is valid and functions are callable
            unsafe {
                let fn_ptr = ptr::read(fn_ptr_addr as *const u64);
                if fn_ptr != 0 && fn_ptr != u64::MAX {
                    let init_fn: InitFn = core::mem::transmute(fn_ptr);
                    init_fn();
                }
            }
        }

        Ok(count)
    }

    pub fn total_init_count(&self) -> usize {
        let preinit = self.preinit_array.as_ref().map(|i| i.count()).unwrap_or(0);
        let init = if self.init_fn.is_some() { 1 } else { 0 };
        let init_array = self.init_array.as_ref().map(|i| i.count()).unwrap_or(0);

        preinit + init + init_array
    }
}

impl Default for InitArrayRunner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn run_init_array(addr: VirtAddr, size: usize) -> ElfResult<usize> {
    if size == 0 {
        return Ok(0);
    }

    let count = size / INIT_FN_SIZE;

    for i in 0..count {
        let fn_ptr_addr = addr.as_u64() + (i * INIT_FN_SIZE) as u64;

        // SAFETY: Caller ensures init array is valid and functions are callable
        unsafe {
            let fn_ptr = ptr::read(fn_ptr_addr as *const u64);
            if fn_ptr != 0 && fn_ptr != u64::MAX {
                let init_fn: InitFn = core::mem::transmute(fn_ptr);
                init_fn();
            }
        }
    }

    Ok(count)
}

pub fn call_init_function(addr: VirtAddr) -> ElfResult<()> {
    if addr.as_u64() == 0 {
        return Err(ElfError::InvalidAddress);
    }

    // SAFETY: Caller ensures init function is valid and callable
    unsafe {
        let init_fn: InitFn = core::mem::transmute(addr.as_u64());
        init_fn();
    }

    Ok(())
}
