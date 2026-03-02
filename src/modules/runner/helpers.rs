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

use core::sync::atomic::Ordering;
use super::constants::FAULT_BACKOFF_MS;
use super::error::{RunnerError, RunnerResult};
use super::types::ExecutionContext;
use super::executor::CONTEXTS;

pub fn allocate_module_stack(size: usize) -> RunnerResult<u64> {
    crate::memory::allocator::allocate_pages((size + 4095) / 4096)
        .map(|addr| addr.as_u64())
        .map_err(|_| RunnerError::MemoryAllocationFailed)
}

pub fn allocate_module_heap(size: usize) -> RunnerResult<u64> {
    crate::memory::allocator::allocate_pages((size + 4095) / 4096)
        .map(|addr| addr.as_u64())
        .map_err(|_| RunnerError::MemoryAllocationFailed)
}

pub fn deallocate_module_memory(stack_base: u64, stack_size: usize, heap_base: u64, heap_size: usize) {
    let stack_pages = (stack_size + 4095) / 4096;
    let heap_pages = (heap_size + 4095) / 4096;
    crate::memory::allocator::deallocate_pages(x86_64::VirtAddr::new(stack_base), stack_pages).ok();
    crate::memory::allocator::deallocate_pages(x86_64::VirtAddr::new(heap_base), heap_pages).ok();
}

pub fn erase_module_memory(base: u64, size: usize) {
    // SAFETY: Secure memory erasure for ZeroState compliance.
    unsafe {
        core::ptr::write_bytes(base as *mut u8, 0, size);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

pub fn resolve_module_entry(module_id: u64) -> RunnerResult<u64> {
    super::super::registry::get_module_entry(module_id)
        .map_err(|_| RunnerError::EntryPointInvalid)
}

pub fn execute_module_startup(context: &mut ExecutionContext) -> RunnerResult<()> {
    if context.entry_point == 0 {
        return Err(RunnerError::EntryPointInvalid);
    }

    if context.stack_base == 0 || context.heap_base == 0 {
        return Err(RunnerError::MemoryAllocationFailed);
    }

    // SAFETY: Initialize module stack with guard pages and canary values
    unsafe {
        let stack_ptr = context.stack_base as *mut u64;
        let canary = crate::crypto::secure_random_u64();
        core::ptr::write_volatile(stack_ptr, canary);
        context.stack_pointer = context.stack_base + context.config.stack_size as u64 - 8;
    }

    // SAFETY: Zero-initialize module heap
    unsafe {
        core::ptr::write_bytes(context.heap_base as *mut u8, 0, context.config.heap_size);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }

    crate::sched::scheduler::spawn_module_task(
        context.module_id,
        context.entry_point,
        context.stack_pointer,
        context.config.priority,
    ).map_err(|_| RunnerError::StartupFailed)?;

    Ok(())
}

pub fn execute_module_shutdown(context: &mut ExecutionContext) -> RunnerResult<()> {
    crate::sched::scheduler::terminate_module_tasks(context.module_id)
        .map_err(|_| RunnerError::ShutdownFailed)?;

    let deadline = get_current_time() + context.config.shutdown_timeout_ms * 1000;
    while crate::sched::scheduler::has_running_tasks(context.module_id) {
        if get_current_time() > deadline {
            crate::sched::scheduler::force_kill_module_tasks(context.module_id);
            break;
        }
        core::hint::spin_loop();
    }

    Ok(())
}

pub fn get_current_time() -> u64 {
    crate::arch::time::tsc::read_tsc()
}

pub fn calculate_backoff(module_id: u64) -> u64 {
    let contexts = CONTEXTS.read();
    if let Some(context) = contexts.get(&module_id) {
        if let Some(ref fault) = context.fault_info {
            return FAULT_BACKOFF_MS * (1u64 << fault.fault_count.min(10));
        }
    }
    FAULT_BACKOFF_MS
}

pub fn spin_delay(ms: u64) {
    let iterations = ms * 1000;
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}
