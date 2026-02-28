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

use super::error::{TscError, TscResult};
use super::asm::rdtsc;
use super::conversion::ns_to_ticks;
use super::state::FEATURES;

pub fn write_deadline(deadline: u64) -> TscResult<()> {
    if !FEATURES.read().deadline_mode {
        return Err(TscError::DeadlineModeUnavailable);
    }

    // SAFETY: WRMSR to IA32_TSC_DEADLINE is safe when TSC deadline mode is available.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0x6E0u32,
            in("eax") (deadline & 0xFFFFFFFF) as u32,
            in("edx") (deadline >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }

    Ok(())
}

pub fn read_deadline() -> TscResult<u64> {
    if !FEATURES.read().deadline_mode {
        return Err(TscError::DeadlineModeUnavailable);
    }

    let lo: u32;
    let hi: u32;
    // SAFETY: RDMSR from IA32_TSC_DEADLINE is safe when TSC deadline mode is available.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0x6E0u32,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags)
        );
    }

    Ok(((hi as u64) << 32) | (lo as u64))
}

pub fn set_deadline_ns(delay_ns: u64) -> TscResult<()> {
    let current = rdtsc();
    let ticks = ns_to_ticks(delay_ns);
    let deadline = current.saturating_add(ticks);
    write_deadline(deadline)
}

pub fn clear_deadline() -> TscResult<()> {
    write_deadline(0)
}
