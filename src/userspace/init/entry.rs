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

use crate::sys::boot_log;
use super::service_list::*;
use super::supervisor::init_loop;
use super::spawner::{spawn_services, spawn_driver_services, spawn_core_services};

pub fn run_init() -> ! {
    boot_log::ok("INIT", "Starting");
    spawn_driver_services(DRIVER_SERVICES);
    crate::sys::serial::println(b"[INIT] Yielding to drivers...");
    for i in 0..50 {
        if i == 0 || i == 25 || i == 49 {
            crate::sys::serial::print(b"[INIT] yield ");
            crate::sys::serial::print_dec(i as u64);
            crate::sys::serial::println(b"");
        }
        crate::sched::yield_now();
    }
    crate::sys::serial::println(b"[INIT] Driver yields complete");
    spawn_services(KERNEL_SERVICES);
    for _ in 0..50 { crate::sched::yield_now(); }
    spawn_services(CRYPTO_ENGINE_SERVICES);
    for _ in 0..20 { crate::sched::yield_now(); }
    spawn_services(SIGNATURE_SERVICES);
    for _ in 0..20 { crate::sched::yield_now(); }
    spawn_services(PQ_CRYPTO_SERVICES);
    for _ in 0..20 { crate::sched::yield_now(); }
    spawn_services(ZK_SERVICES);
    for _ in 0..50 { crate::sched::yield_now(); }
    spawn_services(SYSTEM_SERVICES);
    for _ in 0..50 { crate::sched::yield_now(); }
    spawn_core_services(CORE_SERVICES);
    boot_log::ok("INIT", "Services spawned");
    lower_init_priority();
    for _ in 0..100 { crate::sched::yield_now(); }
    init_loop()
}

fn lower_init_priority() {
    use crate::process::core::{Priority, PROCESS_TABLE, CURRENT_PID};
    use core::sync::atomic::Ordering;
    let pid = CURRENT_PID.load(Ordering::Relaxed);
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.priority.lock() = Priority::Low;
    }
}
