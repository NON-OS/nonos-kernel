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

use crate::arch::riscv64::cpu;
use crate::arch::riscv64::interrupts::frame::TrapFrame;
use crate::sys::serial;

// Mask sstatus.SIE so the dump cannot be re-entered by an interrupt,
// log the cause tag, dump the frame, halt the hart.
pub fn fatal(tag: &[u8], frame: &TrapFrame) -> ! {
    // SAFETY: csrci is a leaf CSR write that never faults.
    unsafe {
        core::arch::asm!("csrci sstatus, 2", options(nostack));
    }
    serial::print(b"[riscv64] fatal: ");
    serial::println(tag);
    frame.dump();
    cpu::halt()
}
