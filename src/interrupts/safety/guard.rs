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

/// # Safety
/// RAII guard that disables interrupts on creation and restores on drop.
/// Ensures interrupts are properly restored even on panic.
pub struct InterruptGuard {
    was_enabled: bool,
}

impl InterruptGuard {
    /// # Safety
    /// Creates guard by disabling interrupts if enabled.
    fn new() -> Self {
        let was_enabled = interrupts_enabled();
        if was_enabled {
            disable_interrupts();
        }
        Self { was_enabled }
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        if self.was_enabled {
            enable_interrupts();
        }
    }
}

/// # Safety
/// Creates RAII guard that disables interrupts until dropped.
pub fn disable_interrupts_guard() -> InterruptGuard {
    InterruptGuard::new()
}

/// # Safety
/// Checks if interrupts are currently enabled via FLAGS register.
fn interrupts_enabled() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let flags: u64;
        unsafe {
            core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags));
        }
        (flags & 0x200) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// # Safety
/// Disables interrupts via CLI instruction.
fn disable_interrupts() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
/// Enables interrupts via STI instruction.
fn enable_interrupts() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
}
