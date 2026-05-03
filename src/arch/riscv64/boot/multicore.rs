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
use core::sync::atomic::{AtomicU32, Ordering};

use super::info::BootInfo;
use super::stack::setup_stack;

static HARTS_ONLINE: AtomicU32 = AtomicU32::new(1);

pub fn start_secondary_harts(boot_info: &BootInfo) {
    for hart in 0..boot_info.hart_count {
        if hart == boot_info.boot_hart {
            continue;
        }

        let stack_top = super::stack::get_kernel_stack(hart as usize);

        let result =
            crate::arch::riscv64::sbi::hart_start(hart as u64, secondary_entry as u64, stack_top);

        if result.is_ok() {
            super::super::uart::puts(b"[BOOT] Started hart ");
            super::super::uart::putc((b'0' + hart as u8) as char);
            super::super::uart::puts(b"\n");
        }
    }

    while HARTS_ONLINE.load(Ordering::Acquire) < boot_info.hart_count {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn secondary_entry() -> ! {
    let hart_id = hart_id();

    setup_stack(hart_id);

    super::super::cpu::init_cpu();
    super::super::plic::init_plic_hart();
    super::super::timer::init_timer_hart();

    HARTS_ONLINE.fetch_add(1, Ordering::AcqRel);

    super::super::uart::puts(b"[BOOT] Hart ");
    super::super::uart::putc((b'0' + hart_id as u8) as char);
    super::super::uart::puts(b" online\n");

    loop {
        unsafe { asm!("wfi", options(nomem, nostack)) };
    }
}

fn hart_id() -> usize {
    let id: usize;
    unsafe {
        asm!("csrr {}, mhartid", out(reg) id, options(nostack));
    }
    id
}

pub fn online_hart_count() -> u32 {
    HARTS_ONLINE.load(Ordering::Acquire)
}

pub fn is_hart_online(hart: u32) -> bool {
    hart < HARTS_ONLINE.load(Ordering::Acquire)
}

pub fn wait_for_harts(count: u32) {
    while HARTS_ONLINE.load(Ordering::Acquire) < count {
        core::hint::spin_loop();
    }
}
