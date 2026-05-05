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

// Kernel-thread stack pool for legacy `spawn_isolated_service` engines
// only. Real capsules go through
// `kernel_core::process_spawn::user_stack` (USER | WRITE | NX in the
// capsule's address space) plus a per-process kernel stack from
// `kernel_core::process_spawn::kernel_stack`. This pool is kernel VA,
// non-USER, and must never back a CPL=3 entry.
use crate::process::core::Pid;
use core::sync::atomic::{AtomicU32, Ordering};

pub(crate) const SERVICE_STACK_SIZE: usize = 64 * 1024;
const MAX_SERVICE_STACKS: usize = 64;

#[repr(C, align(16))]
struct AlignedStack([u8; SERVICE_STACK_SIZE]);

static mut SERVICE_STACKS: [AlignedStack; MAX_SERVICE_STACKS] = {
    const INIT: AlignedStack = AlignedStack([0u8; SERVICE_STACK_SIZE]);
    [INIT; MAX_SERVICE_STACKS]
};

static NEXT_STACK_IDX: AtomicU32 = AtomicU32::new(0);
static STACK_IN_USE: [AtomicU32; MAX_SERVICE_STACKS] = {
    const INIT: AtomicU32 = AtomicU32::new(0);
    [INIT; MAX_SERVICE_STACKS]
};

pub(crate) fn allocate_service_stack(pid: Pid) -> u64 {
    let idx = NEXT_STACK_IDX.fetch_add(1, Ordering::SeqCst) as usize % MAX_SERVICE_STACKS;
    STACK_IN_USE[idx].store(pid, Ordering::SeqCst);
    let stack_ptr = unsafe { SERVICE_STACKS[idx].0.as_mut_ptr() };
    (stack_ptr as u64) + SERVICE_STACK_SIZE as u64 - 16
}

#[allow(dead_code)]
pub(crate) fn deallocate_service_stack(pid: Pid) {
    for i in 0..MAX_SERVICE_STACKS {
        if STACK_IN_USE[i].compare_exchange(pid, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            return;
        }
    }
}
