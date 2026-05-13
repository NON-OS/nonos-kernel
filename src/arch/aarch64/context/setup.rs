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

use crate::process::core::{Pid, PROCESS_TABLE};

use super::enter::SPSR_EL0T_INITIAL;
use super::types::UserEntry;

// 48-bit canonical user VA (TTBR0 half).
const USER_VA_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;

#[derive(Debug, Clone, Copy)]
pub enum SetupError {
    NoSuchProcess,
    NonUserEntry,
    NonUserStack,
}

// aarch64 builder: SPSR_EL1 = EL0t, IRQ/FIQ/SError unmasked. SP_EL0 =
// user stack top. ELR_EL1 = capsule ELF entry. kernel_sp left zero;
// the scheduler dispatch hook fills it from pcb.kernel_stack_top so
// there's one source of truth. args[] zeroed — capsule ABI passes
// argv/envc/cap-handle through registers populated by the capsule
// loader if non-trivial; the default-zero shape is matched by the
// x86 path which iretqs with the zero-init GPRs from jump_to_usermode.
pub fn setup_initial_user_pcb_aarch64(
    pid: Pid,
    entry: u64,
    user_sp: u64,
) -> Result<(), SetupError> {
    if entry == 0 || entry > USER_VA_MAX {
        return Err(SetupError::NonUserEntry);
    }
    if user_sp == 0 || user_sp > USER_VA_MAX {
        return Err(SetupError::NonUserStack);
    }
    let pcb = PROCESS_TABLE.find_by_pid(pid).ok_or(SetupError::NoSuchProcess)?;
    let entry_ctx = UserEntry {
        entry,
        user_sp,
        spsr: SPSR_EL0T_INITIAL,
        kernel_sp: 0,
        args: [0; 8],
    };
    *pcb.pending_user_entry.lock() = Some(entry_ctx);
    Ok(())
}
