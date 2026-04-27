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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const MAX_CPUS: usize = 256;

/// # Safety
/// Per-CPU fault recovery state. Only the page fault handler and usercopy
/// code should access this. Each CPU has independent state.
struct FaultState {
    active: AtomicBool,
    recovery_rip: AtomicU64,
    faulted: AtomicBool,
}

/// # Safety
/// Static array indexed by CPU ID. Each CPU only writes to its own slot.
static FAULT_STATES: [FaultState; MAX_CPUS] = {
    const INIT: FaultState = FaultState {
        active: AtomicBool::new(false),
        recovery_rip: AtomicU64::new(0),
        faulted: AtomicBool::new(false),
    };
    [INIT; MAX_CPUS]
};

/// # Safety
/// Reads CPU ID from GS segment base. Must be called with valid GS setup.
fn cpu_id() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let id: u64;
        unsafe {
            core::arch::asm!("mov {}, gs:0", out(reg) id, options(nostack, preserves_flags));
        }
        (id as usize) % MAX_CPUS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// # Safety
/// RAII guard that clears fault handler on drop. Ensures fault handler
/// is always cleared even on early return or panic.
pub struct FaultRecovery {
    _cpu: usize,
}

impl Drop for FaultRecovery {
    fn drop(&mut self) {
        clear_fault_handler();
    }
}

/// # Safety
/// Sets up fault recovery for user memory access. The recovery_rip must
/// point to valid code that handles the fault gracefully. Returns guard
/// that clears handler on drop.
pub fn set_fault_handler(recovery_rip: u64) -> FaultRecovery {
    let cpu = cpu_id();
    let state = &FAULT_STATES[cpu];
    state.recovery_rip.store(recovery_rip, Ordering::Release);
    state.faulted.store(false, Ordering::Release);
    state.active.store(true, Ordering::Release);
    FaultRecovery { _cpu: cpu }
}

/// # Safety
/// Clears fault handler for current CPU. Must be called after user memory
/// access is complete to prevent stale handlers.
pub fn clear_fault_handler() {
    let cpu = cpu_id();
    let state = &FAULT_STATES[cpu];
    state.active.store(false, Ordering::Release);
    state.recovery_rip.store(0, Ordering::Release);
}

/// # Safety
/// Called from page fault handler to check if recovery is possible.
/// If active, sets faulted flag and returns recovery RIP. The fault
/// handler should jump to this RIP instead of panicking.
pub fn try_recover_fault() -> Option<u64> {
    let cpu = cpu_id();
    let state = &FAULT_STATES[cpu];
    if state.active.load(Ordering::Acquire) {
        state.faulted.store(true, Ordering::Release);
        Some(state.recovery_rip.load(Ordering::Acquire))
    } else {
        None
    }
}

/// # Safety
/// Returns true if a fault occurred during the current user copy operation.
pub fn did_fault() -> bool {
    let cpu = cpu_id();
    FAULT_STATES[cpu].faulted.load(Ordering::Acquire)
}
