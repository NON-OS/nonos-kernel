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

use super::types::UserEntry;

// Symbol implemented in src/arch/aarch64/asm/enter_user.S.
extern "C" {
    fn aarch64_enter_user(ctx: *const UserEntry) -> !;
}

// SPSR_EL1 value for first entry to an EL0t task. M[3:0]=0 selects
// EL0t. DAIF: all four interrupt-mask bits clear so the task runs with
// IRQ/FIQ/SError unmasked at EL0 (the standard contract for a fresh
// capsule entry). Reserved bits per ARM ARM are 0.
//
//   bit 0  M[0] = 0  (EL0t)
//   bit 1  M[1] = 0
//   bit 2  M[2] = 0
//   bit 3  M[3] = 0
//   bit 6  F  = 0
//   bit 7  I  = 0
//   bit 8  A  = 0
//   bit 9  D  = 0
//
// = 0
pub const SPSR_EL0T_INITIAL: u64 = 0;

// Canonical user VA upper bound. TTBR0 covers 0..2^48-1 on the typical
// 48-bit VA setup; anything above this is the kernel half via TTBR1.
const USER_VA_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;

#[derive(Debug, Clone, Copy)]
pub enum EnterError {
    NonUserEntry,
    NonUserStack,
    NoKernelStack,
}

// Hand control to EL0 with the supplied entry, user sp, args, and per-
// task kernel sp top. Validation rejects kernel VAs in `entry`/`user_sp`
// and a zero kernel sp (which would land a subsequent trap on no stack
// at all). Caller has masked IRQs and installed the right address
// space; this function does not return.
//
// SAFETY: caller guarantees that `entry` is mapped and executable at
// EL0 in the current address space, that `user_sp` is mapped writable
// at EL0, and that `kernel_sp` points to a kernel stack top that holds
// at least one trap frame's worth of growth.
pub unsafe fn enter_user(ctx: &UserEntry) -> Result<core::convert::Infallible, EnterError> {
    if ctx.entry == 0 || ctx.entry > USER_VA_MAX {
        return Err(EnterError::NonUserEntry);
    }
    if ctx.user_sp == 0 || ctx.user_sp > USER_VA_MAX {
        return Err(EnterError::NonUserStack);
    }
    if ctx.kernel_sp == 0 {
        return Err(EnterError::NoKernelStack);
    }
    unsafe { aarch64_enter_user(ctx as *const _) }
}
