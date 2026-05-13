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

use core::arch::asm;

use crate::arch::riscv64::cpu::csr::{SSTATUS_FS_DIRTY, SSTATUS_FS_INITIAL, SSTATUS_FS_MASK};

// Move sstatus.FS to Initial. The first FP write after this point
// will set FS=Dirty so the save path knows the registers are live.
pub fn enable_initial() {
    set_fs(SSTATUS_FS_INITIAL);
}

// Move sstatus.FS to Off. Future FP ops trap (illegal-instruction).
pub fn disable() {
    set_fs(0);
}

// Move sstatus.FS to Dirty. Used by save paths that need to read the
// registers and then promote so the next deschedule re-saves.
pub fn mark_dirty() {
    set_fs(SSTATUS_FS_DIRTY);
}

fn set_fs(fs_bits: usize) {
    let mut sstatus: usize;
    unsafe {
        asm!("csrr {}, sstatus", out(reg) sstatus, options(nomem, nostack));
    }
    sstatus = (sstatus & !SSTATUS_FS_MASK) | fs_bits;
    unsafe {
        asm!("csrw sstatus, {}", in(reg) sstatus, options(nomem, nostack));
    }
}
