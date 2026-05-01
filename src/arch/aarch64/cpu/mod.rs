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

pub mod features;
pub mod id;
pub mod state;

pub use features::{has_feature, CpuFeature};
pub use id::{cpu_id, core_id, cluster_id};
pub use state::{current_el, is_el1, is_el2};

use core::arch::asm;

pub fn init_cpu() {
    configure_sctlr();
    enable_fp_simd();
    configure_cache();
}

fn configure_sctlr() {
    let mut sctlr: u64;
    unsafe {
        asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nostack));
    }

    sctlr |= 1 << 0;
    sctlr |= 1 << 2;
    sctlr |= 1 << 12;
    sctlr |= 1 << 26;
    sctlr &= !(1 << 19);

    unsafe {
        asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));
        asm!("isb", options(nostack));
    }
}

fn enable_fp_simd() {
    unsafe {
        asm!(
            "mrs x0, cpacr_el1",
            "orr x0, x0, #(3 << 20)",
            "msr cpacr_el1, x0",
            "isb",
            out("x0") _,
            options(nostack)
        );
    }
}

fn configure_cache() {
    unsafe {
        asm!("ic iallu", options(nostack));
        asm!("dsb ish", options(nostack));
        asm!("isb", options(nostack));
    }
}

pub fn halt() -> ! {
    loop {
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}

pub fn wait_for_event() {
    unsafe {
        asm!("wfe", options(nomem, nostack));
    }
}

pub fn send_event() {
    unsafe {
        asm!("sev", options(nomem, nostack));
    }
}

pub fn enable_interrupts() {
    unsafe {
        asm!("msr daifclr, #0xf", options(nostack));
    }
}

pub fn disable_interrupts() {
    unsafe {
        asm!("msr daifset, #0xf", options(nostack));
    }
}

pub fn interrupts_enabled() -> bool {
    let daif: u64;
    unsafe {
        asm!("mrs {}, daif", out(reg) daif, options(nostack));
    }
    (daif & 0x3C0) == 0
}

pub fn memory_barrier() {
    unsafe {
        asm!("dmb sy", options(nostack));
    }
}

pub fn instruction_barrier() {
    unsafe {
        asm!("isb", options(nostack));
    }
}

pub fn data_sync_barrier() {
    unsafe {
        asm!("dsb sy", options(nostack));
    }
}
