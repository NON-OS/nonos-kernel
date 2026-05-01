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

static CPUS_ONLINE: AtomicU32 = AtomicU32::new(1);

pub fn start_secondary_cpus(boot_info: &BootInfo) {
    for cpu in 1..boot_info.cpu_count {
        let stack_top = super::stack::get_kernel_stack(cpu as usize);

        let result = crate::arch::aarch64::psci::cpu_on(
            cpu as u64,
            secondary_entry as u64,
            stack_top,
        );

        if result.is_ok() {
            super::super::uart::puts(b"[BOOT] Started CPU ");
            super::super::uart::putc((b'0' + cpu as u8) as char);
            super::super::uart::puts(b"\n");
        }
    }

    while CPUS_ONLINE.load(Ordering::Acquire) < boot_info.cpu_count {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn secondary_entry() -> ! {
    let cpu_id = get_cpu_id();

    setup_stack(cpu_id);

    super::super::cpu::init_cpu();
    super::super::gic::init_gic_cpu();
    super::super::timer::init_timer_cpu();

    CPUS_ONLINE.fetch_add(1, Ordering::AcqRel);

    super::super::uart::puts(b"[BOOT] CPU ");
    super::super::uart::putc((b'0' + cpu_id as u8) as char);
    super::super::uart::puts(b" online\n");

    loop {
        unsafe { asm!("wfe", options(nomem, nostack)) };
    }
}

fn get_cpu_id() -> usize {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack));
    }
    (mpidr & 0xFF) as usize
}

pub fn online_cpu_count() -> u32 {
    CPUS_ONLINE.load(Ordering::Acquire)
}

pub fn is_cpu_online(cpu: u32) -> bool {
    cpu < CPUS_ONLINE.load(Ordering::Acquire)
}

pub fn wait_for_cpus(count: u32) {
    while CPUS_ONLINE.load(Ordering::Acquire) < count {
        core::hint::spin_loop();
    }
}
