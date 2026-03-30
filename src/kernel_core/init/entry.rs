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

use core::sync::atomic::Ordering;
use crate::sys::{clock, boot_log};
use crate::boot::handoff::BootHandoffV1;
use crate::process::core::{create_process, ProcessState, Priority, CURRENT_PID};
use crate::memory::paging::manager::api::create_address_space;
use super::memory::init_memory;
use super::framebuffer::init_framebuffer;

pub fn microkernel_init(handoff: &BootHandoffV1) {
    init_memory(handoff);
    let _ = crate::memory::paging::manager::api::init();
    init_framebuffer(handoff);
    boot_log::init_after_fb();
    boot_log::ok("NONOS", "Microkernel init");
    crate::ipc::init();
    crate::syscall::microkernel::capability::init_cap_for_init();
    crate::sched::init();
    clock::init(handoff.timing.tsc_hz, handoff.timing.unix_epoch_ms);
    boot_log::ok("NONOS", "Core ready");
}

pub fn microkernel_main() -> ! {
    boot_log::ok("UKERNEL", "Creating init");
    let init_pid = create_process("init", ProcessState::Running, Priority::High)
        .unwrap_or_else(|_| loop { core::hint::spin_loop(); });
    let _ = create_address_space(init_pid);
    CURRENT_PID.store(init_pid, Ordering::SeqCst);
    boot_log::ok("UKERNEL", "Entering userspace");
    crate::userspace::run_init()
}
