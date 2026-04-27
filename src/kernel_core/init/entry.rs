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

use super::framebuffer::init_framebuffer;
use super::memory::init_memory;
use crate::boot::handoff::BootHandoffV1;
use crate::memory::paging::manager::api::create_address_space;
use crate::process::core::{create_process, Priority, ProcessState, CURRENT_PID};
use crate::sys::{boot_log, clock};
use core::sync::atomic::Ordering;

pub fn microkernel_init(handoff: &BootHandoffV1) {
    init_memory(handoff);
    init_framebuffer(handoff);
    boot_log::init_after_fb(handoff.fb.cursor_y);
    boot_log::ok("NONOS", "Microkernel init");
    crate::sys::settings::init();
    crate::locale::init_from_settings();
    crate::sys::settings::init_hostname();
    crate::ipc::init();
    crate::ipc::nonos_channel::init_ipc_secret();
    crate::syscall::microkernel::capability::init_cap_for_init();
    crate::sched::init();
    clock::init(handoff.timing.tsc_hz, handoff.timing.unix_epoch_ms);
    crate::process::init_process_management();
    let _ = crate::crypto::util::rng::init_rng();
    crate::crypto::kernel_keys::init();
    crate::network::stack::init_network_stack();
    boot_log::ok("NET", "stack created (early)");
    boot_log::ok("NONOS", "Core ready");
}

pub fn microkernel_main() -> ! {
    boot_log::ok("UKERNEL", "Creating init");
    let init_pid = match create_process("init", ProcessState::Running, Priority::High) {
        Ok(pid) => pid,
        Err(e) => {
            boot_log::error("Failed to create init process");
            crate::sys::serial::println(b"[FATAL] Init process creation failed");
            crate::sys::serial::println(e.as_bytes());
            crate::arch::x86_64::boot::cpu_ops::halt_loop()
        }
    };
    if let Err(_) = create_address_space(init_pid) {
        boot_log::error("Failed to create init address space");
        crate::sys::serial::println(b"[FATAL] Init address space creation failed");
        crate::arch::x86_64::boot::cpu_ops::halt_loop()
    }
    CURRENT_PID.store(init_pid, Ordering::SeqCst);
    boot_log::ok("UKERNEL", "Entering userspace");
    crate::userspace::run_init()
}
