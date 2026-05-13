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

pub mod caps;
pub mod csr;
pub mod extensions;
pub mod id;

pub use csr::{clear_csr, read_csr, set_csr, write_csr};
pub use id::{cpu_id, hart_id, marchid, mimpid, mvendorid};

use core::arch::asm;

pub fn init_cpu() {
    configure_sstatus();
    configure_sie();
}

fn configure_sstatus() {
    unsafe {
        let mut sstatus: usize;
        asm!("csrr {}, sstatus", out(reg) sstatus, options(nostack));

        sstatus |= 1 << 18;
        sstatus |= 1 << 19;

        asm!("csrw sstatus, {}", in(reg) sstatus, options(nostack));
    }
}

fn configure_sie() {
    unsafe {
        let sie: usize = (1 << 1) | (1 << 5) | (1 << 9);
        asm!("csrw sie, {}", in(reg) sie, options(nostack));
    }
}

pub fn halt() -> ! {
    loop {
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}

pub fn wait_for_interrupt() {
    unsafe {
        asm!("wfi", options(nomem, nostack));
    }
}

pub fn enable_interrupts() {
    unsafe {
        asm!("csrsi sstatus, 2", options(nostack));
    }
}

pub fn disable_interrupts() {
    unsafe {
        asm!("csrci sstatus, 2", options(nostack));
    }
}

pub fn interrupts_enabled() -> bool {
    let sstatus: usize;
    unsafe {
        asm!("csrr {}, sstatus", out(reg) sstatus, options(nostack));
    }
    (sstatus & (1 << 1)) != 0
}

pub fn fence() {
    unsafe {
        asm!("fence", options(nostack));
    }
}

pub fn fence_i() {
    unsafe {
        asm!("fence.i", options(nostack));
    }
}

pub fn sfence_vma() {
    unsafe {
        asm!("sfence.vma", options(nostack));
    }
}

pub fn sfence_vma_addr(addr: usize) {
    unsafe {
        asm!("sfence.vma {}, zero", in(reg) addr, options(nostack));
    }
}

pub fn sfence_vma_asid(asid: usize) {
    unsafe {
        asm!("sfence.vma zero, {}", in(reg) asid, options(nostack));
    }
}

pub fn sfence_vma_addr_asid(addr: usize, asid: usize) {
    unsafe {
        asm!("sfence.vma {}, {}", in(reg) addr, in(reg) asid, options(nostack));
    }
}
