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
use crate::sys::{serial, clock};
use crate::boot::handoff::BootHandoffV1;
use crate::process::core::{create_process, ProcessState, Priority, CURRENT_PID};
use crate::memory::paging::manager::api::create_address_space;
use super::memory::init_memory;
use super::framebuffer::init_framebuffer;

pub fn microkernel_init(handoff: &BootHandoffV1) {
    serial::println(b"[UKERNEL] Microkernel core init");
    init_memory(handoff);
    serial::println(b"[UKERNEL] Memory initialized");
    if crate::memory::paging::manager::api::init().is_err() {
        serial::println(b"[UKERNEL] Paging init failed");
    }
    serial::println(b"[UKERNEL] Paging initialized");
    crate::ipc::init();
    serial::println(b"[UKERNEL] IPC ready");
    crate::syscall::microkernel::capability::init_cap_for_init();
    serial::println(b"[UKERNEL] Capabilities initialized");
    crate::sched::init();
    serial::println(b"[UKERNEL] Scheduler initialized");
    clock::init(handoff.timing.tsc_hz, handoff.timing.unix_epoch_ms);
    serial::println(b"[UKERNEL] Clock initialized");
    init_framebuffer(handoff);
    serial::println(b"[UKERNEL] Framebuffer initialized");
}

pub fn microkernel_main() -> ! {
    serial::println(b"[UKERNEL] Creating init process");
    let init_pid = match create_process("init", ProcessState::Running, Priority::High) {
        Ok(pid) => pid,
        Err(_) => {
            serial::println(b"[UKERNEL] Failed to create init process");
            loop { core::hint::spin_loop(); }
        }
    };
    serial::print(b"[UKERNEL] Init PID: ");
    serial::print_dec(init_pid as u64);
    serial::println(b"");
    let _ = create_address_space(init_pid);
    CURRENT_PID.store(init_pid, Ordering::SeqCst);
    serial::println(b"[UKERNEL] Entering userspace init");
    crate::userspace::run_init()
}
