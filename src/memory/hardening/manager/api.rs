// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::types::*;
use super::core::{HARDENING_STATS, MEMORY_HARDENING};
pub use super::init::init;
use crate::memory::layout;
use x86_64::VirtAddr;

pub fn validate_memory_permissions(
    addr: VirtAddr,
    writable: bool,
    executable: bool,
) -> Result<(), &'static str> {
    MEMORY_HARDENING.validate_wx_permissions(addr, writable, executable)
}

pub fn check_guard_page_access(addr: VirtAddr) -> bool {
    if MEMORY_HARDENING.check_guard_page_violation(addr) {
        HARDENING_STATS.increment_guard_violations();
        true
    } else {
        false
    }
}

pub fn track_allocation(addr: u64, size: usize) -> u64 {
    MEMORY_HARDENING.track_allocation(addr, size)
}
pub fn track_deallocation(addr: u64) -> Result<(), &'static str> {
    MEMORY_HARDENING.track_deallocation(addr)
}
pub fn check_stack_canary(stack_base: VirtAddr) -> Result<(), &'static str> {
    MEMORY_HARDENING.check_stack_integrity(stack_base)
}
pub fn validate_heap_integrity(addr: u64, size: usize) -> Result<(), &'static str> {
    MEMORY_HARDENING.detect_heap_corruption(addr, size)
}

pub fn add_guard_page(addr: VirtAddr, guard_type: GuardType) -> Result<(), &'static str> {
    let guard = GuardPage { addr, size: layout::PAGE_SIZE, protection_type: guard_type };
    MEMORY_HARDENING.guard_pages.write().insert(addr.as_u64(), guard);
    Ok(())
}

pub fn remove_guard_page(addr: VirtAddr) -> Result<(), &'static str> {
    if MEMORY_HARDENING.guard_pages.write().remove(&addr.as_u64()).is_some() {
        Ok(())
    } else {
        Err("Guard page not found")
    }
}

pub fn get_hardening_stats() -> HardeningStatsSnapshot {
    HardeningStatsSnapshot {
        guard_violations: HARDENING_STATS.guard_violations(),
        wx_violations: HARDENING_STATS.wx_violations(),
        stack_overflows: HARDENING_STATS.stack_overflows(),
        heap_corruptions: HARDENING_STATS.heap_corruptions(),
        double_frees: HARDENING_STATS.double_frees(),
        use_after_free: HARDENING_STATS.use_after_free(),
        total_guard_pages: MEMORY_HARDENING.guard_pages.read().len(),
        active_canaries: MEMORY_HARDENING.stack_canaries.read().len(),
        tracked_allocations: MEMORY_HARDENING.allocation_tracker.lock().len(),
    }
}

pub fn setup_stack_canary(stack_base: VirtAddr, stack_size: usize) -> Result<u64, &'static str> {
    let canary_value = MEMORY_HARDENING.generate_stack_canary();
    let canary = StackCanary { value: canary_value, stack_base, stack_size };
    MEMORY_HARDENING.stack_canaries.write().insert(stack_base.as_u64(), canary);
    unsafe {
        let canary_location = (stack_base.as_u64() + stack_size as u64 - 8) as *mut u64;
        canary_location.write_volatile(canary_value);
    }
    Ok(canary_value)
}

pub fn clear_stack_canary(stack_base: VirtAddr) -> Result<(), &'static str> {
    if MEMORY_HARDENING.stack_canaries.write().remove(&stack_base.as_u64()).is_some() {
        Ok(())
    } else {
        Err("Stack canary not found")
    }
}
