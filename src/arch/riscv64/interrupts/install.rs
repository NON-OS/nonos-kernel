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

use crate::arch::riscv64::asm::trap_entry_addr;
use crate::arch::riscv64::cpu::csr::{write_csr, STVEC};

// stvec encoding: bits[63:2]=BASE (4-byte aligned), bits[1:0]=MODE.
// MODE=0 (Direct) — every trap branches to BASE; the dispatcher
// decodes scause. Vectored mode is unused until per-cause tables exist.
const STVEC_MODE_DIRECT: usize = 0;

pub fn install_stvec() {
    let base = trap_entry_addr();
    // Asm enforces 4-byte alignment via `.balign 4`; assert before
    // committing so a future linker placement bug fails closed.
    assert!(base & 0x3 == 0, "trap entry not 4-byte aligned");
    write_csr(STVEC, base | STVEC_MODE_DIRECT);
}
