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
use core::sync::atomic::{compiler_fence, Ordering};
use spin::Mutex;
use super::constants::*;
use super::error::{SandboxError, SandboxResult};
use super::types::{SandboxConfig, SandboxState};

static SANDBOXES: Mutex<Vec<SandboxState>> = Mutex::new(Vec::new());

pub fn setup_sandbox(module_id: u64, config: &SandboxConfig) -> SandboxResult<()> {
    if config.memory_limit == 0 {
        return Err(SandboxError::ZeroMemoryLimit);
    }

    if config.memory_limit > MAX_MEMORY_LIMIT {
        return Err(SandboxError::MemoryLimitExceeded);
    }

    let mut sandboxes = SANDBOXES.lock();

    if sandboxes.len() >= MAX_SANDBOXES {
        return Err(SandboxError::TooManySandboxes);
    }

    if sandboxes.iter().any(|s| s.module_id == module_id) {
        return Err(SandboxError::SandboxAlreadyExists);
    }

    let page_count = config.page_count();
    let base_addr = crate::memory::allocator::allocate_pages(page_count)
        .map_err(|_| SandboxError::AllocationFailed)?;

    // SAFETY: Zero the allocated memory
    unsafe {
        let ptr = base_addr.as_u64() as *mut u8;
        core::ptr::write_bytes(ptr, 0, config.memory_limit);
    }
    compiler_fence(Ordering::SeqCst);

    let state = SandboxState::new(
        module_id,
        base_addr.as_u64() as usize,
        config.memory_limit,
        config.allowed_capabilities.clone(),
    );

    sandboxes.push(state);
    Ok(())
}

pub fn destroy_sandbox(module_id: u64) -> SandboxResult<()> {
    let mut sandboxes = SANDBOXES.lock();

    let idx = sandboxes
        .iter()
        .position(|s| s.module_id == module_id)
        .ok_or(SandboxError::SandboxNotFound)?;

    let state = sandboxes.remove(idx);

    // SAFETY: Securely erase sandbox memory before freeing
    unsafe {
        let ptr = state.base_addr as *mut u8;
        for i in 0..state.size {
            core::ptr::write_volatile(ptr.add(i), 0);
        }
    }
    compiler_fence(Ordering::SeqCst);

    crate::memory::allocator::free_pages(
        x86_64::VirtAddr::new(state.base_addr as u64),
        state.page_count(),
    )
    .map_err(|_| SandboxError::EraseFailed)?;

    Ok(())
}

pub fn is_sandbox_active(module_id: u64) -> bool {
    let sandboxes = SANDBOXES.lock();
    sandboxes
        .iter()
        .any(|s| s.module_id == module_id && s.active)
}

pub fn list_active_sandboxes() -> Vec<u64> {
    let sandboxes = SANDBOXES.lock();
    sandboxes
        .iter()
        .filter(|s| s.active)
        .map(|s| s.module_id)
        .collect()
}

pub fn get_sandbox_memory(module_id: u64) -> Option<(usize, usize)> {
    let sandboxes = SANDBOXES.lock();
    sandboxes
        .iter()
        .find(|s| s.module_id == module_id)
        .map(|s| (s.base_addr, s.size))
}

pub fn sandbox_has_capability(module_id: u64, capability: u64) -> bool {
    let sandboxes = SANDBOXES.lock();
    sandboxes
        .iter()
        .find(|s| s.module_id == module_id)
        .map(|s| s.has_capability(capability))
        .unwrap_or(false)
}

pub fn sandbox_count() -> usize {
    let sandboxes = SANDBOXES.lock();
    sandboxes.len()
}
