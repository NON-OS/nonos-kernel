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

extern crate alloc;

use super::vga_error::halt_loop;

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    crate::boot::init_vga_output();
    crate::boot::init_panic_handler();
    crate::boot::init_early();

    init_smp_bsp();

    // Legacy bring-up: the broad driver stack, the legacy security
    // monitor, the in-kernel filesystem, the desktop framebuffer, and
    // the optional zksync/runtime/npkg paths. None of these are part
    // of the microkernel trusted path; the boot path here is
    // pci/virtio_rng (already done in `init_core_systems`), then
    // straight to the scheduler.

    init_smp_aps();

    #[cfg(feature = "sched")]
    {
        crate::sched::enter();
    }

    #[cfg(not(feature = "sched"))]
    halt_loop();
}

fn init_smp_bsp() {
    #[cfg(target_arch = "x86_64")]
    {
        if let Err(e) = crate::smp::init_bsp() {
            crate::log_warn!("SMP BSP init: {}", e);
        }
    }
}

fn init_smp_aps() {
    #[cfg(target_arch = "x86_64")]
    {
        match crate::smp::start_aps() {
            Ok(count) => {
                if count > 0 {
                        count
                    ));
                }
            }
            Err(e) => crate::log_warn!("SMP AP startup: {}", e),
        }
    }
}

