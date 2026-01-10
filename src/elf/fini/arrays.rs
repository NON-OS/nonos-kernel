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

pub type FiniFn = unsafe extern "C" fn();

pub const FINI_FN_SIZE: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct FiniArrayInfo {
    pub addr: VirtAddr,
    pub size: usize,
}

impl FiniArrayInfo {
    pub fn new(addr: VirtAddr, size: usize) -> Self {
        Self { addr, size }
    }

    pub fn count(&self) -> usize {
        self.size / FINI_FN_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

pub struct FiniArrayRunner {
    fini_array: Option<FiniArrayInfo>,
    fini_fn: Option<VirtAddr>,
}

impl FiniArrayRunner {
    pub fn new() -> Self {
        Self { fini_array: None, fini_fn: None }
    }

    pub fn with_fini_array(mut self, info: FiniArrayInfo) -> Self {
        self.fini_array = Some(info);
        self
    }

    pub fn with_fini_fn(mut self, addr: VirtAddr) -> Self {
        self.fini_fn = Some(addr);
        self
    }

    pub fn run_all(&self) -> ElfResult<usize> {
        let mut count = 0;

        count += self.run_fini_array()?;
        count += self.run_fini_fn()?;

        Ok(count)
    }

    pub fn run_fini_array(&self) -> ElfResult<usize> {
        let Some(ref info) = self.fini_array else {
            return Ok(0);
        };

        if info.is_empty() {
            return Ok(0);
        }

        let count = info.count();

        for i in (0..count).rev() {
            let fn_ptr_addr = info.addr.as_u64() + (i * FINI_FN_SIZE) as u64;
            // SAFETY: Caller ensures fini array is valid and functions are callable
            unsafe {
                let fn_ptr = ptr::read(fn_ptr_addr as *const u64);
                if fn_ptr != 0 && fn_ptr != u64::MAX {
                    let fini_fn: FiniFn = core::mem::transmute(fn_ptr);
                    fini_fn();
                }
            }
        }

        Ok(count)
    }

    pub fn run_fini_fn(&self) -> ElfResult<usize> {
        let Some(addr) = self.fini_fn else {
            return Ok(0);
        };

        if addr.as_u64() == 0 {
            return Ok(0);
        }

        // SAFETY: Caller ensures fini function is valid and callable
        unsafe {
            let fini_fn: FiniFn = core::mem::transmute(addr.as_u64());
            fini_fn();
        }

        Ok(1)
    }

    pub fn total_fini_count(&self) -> usize {
        let fini_array = self.fini_array.as_ref().map(|i| i.count()).unwrap_or(0);
        let fini = if self.fini_fn.is_some() { 1 } else { 0 };

        fini_array + fini
    }
}

impl Default for FiniArrayRunner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn run_fini_array(addr: VirtAddr, size: usize) -> ElfResult<usize> {
    if size == 0 {
        return Ok(0);
    }

    let count = size / FINI_FN_SIZE;

    for i in (0..count).rev() {
        let fn_ptr_addr = addr.as_u64() + (i * FINI_FN_SIZE) as u64;
        // SAFETY: Caller ensures fini array is valid and functions are callable
        unsafe {
            let fn_ptr = ptr::read(fn_ptr_addr as *const u64);
            if fn_ptr != 0 && fn_ptr != u64::MAX {
                let fini_fn: FiniFn = core::mem::transmute(fn_ptr);
                fini_fn();
            }
        }
    }

    Ok(count)
}

pub fn call_fini_function(addr: VirtAddr) -> ElfResult<()> {
    if addr.as_u64() == 0 {
        return Err(ElfError::InvalidAddress);
    }

    // SAFETY: Caller ensures fini function is valid and callable
    unsafe {
        let fini_fn: FiniFn = core::mem::transmute(addr.as_u64());
        fini_fn();
    }

    Ok(())
}
