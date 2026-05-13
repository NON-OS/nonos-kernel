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
use crate::arch::riscv64::cpu::csr::{SSTATUS_SPIE, SSTATUS_SPP};

extern "C" {
    fn riscv64_enter_user(ctx: *const UserEntry) -> !;
}

// Baseline sstatus for first U-mode entry:
//   SPP=0     -> sret returns to U-mode
//   SPIE=1    -> SIE=1 after sret (interrupts on in user)
//   SIE=0     -> S-mode interrupts masked until sret swaps in SPIE
//   FS=00     -> FP off; lazy-enable trap delivers fail-closed fault
//   VS=00     -> V off; same fail-closed
pub const SSTATUS_USER_INITIAL: u64 = SSTATUS_SPIE as u64;

// Sv39/Sv48 canonical user range. The kernel half is everything with
// bit 38/47 set on the respective layout; we treat anything above the
// usable user maximum as kernel and refuse.
const USER_VA_MAX_SV39: u64 = (1u64 << 38) - 1;

#[derive(Debug, Clone, Copy)]
pub enum EnterError {
    NonUserEntry,
    NonUserStack,
    NoKernelStack,
    SstatusWouldStayInSMode,
}

// Hand control to U-mode. Refuses kernel VAs and any sstatus value that
// would not return to U-mode after sret. Caller has masked SIE and
// installed satp; on success this function does not return.
pub unsafe fn enter_user(ctx: &UserEntry) -> Result<core::convert::Infallible, EnterError> {
    if ctx.entry == 0 || ctx.entry > USER_VA_MAX_SV39 {
        return Err(EnterError::NonUserEntry);
    }
    if ctx.user_sp == 0 || ctx.user_sp > USER_VA_MAX_SV39 {
        return Err(EnterError::NonUserStack);
    }
    if ctx.kernel_sp == 0 {
        return Err(EnterError::NoKernelStack);
    }
    if (ctx.sstatus & SSTATUS_SPP as u64) != 0 {
        return Err(EnterError::SstatusWouldStayInSMode);
    }
    unsafe { riscv64_enter_user(ctx as *const _) }
}
