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

use crate::kernel_core::spawn_isolated_service;
use crate::services::caps::{CAP_VFS, CAP_NET, CAP_DISPLAY, CAP_DRIVER, CAP_CRYPTO, CAP_INPUT, CAP_ZK};
use super::service_list::{CORE_SERVICES, DRIVER_SERVICES};
use super::supervisor::init_loop;

pub fn run_init() -> ! {
    crate::sys::serial::println(b"[INIT] Init process starting");
    crate::sys::serial::println(b"[INIT] Spawning core services...");
    spawn_core_services();
    crate::sys::serial::println(b"[INIT] Spawning driver services...");
    spawn_driver_services();
    crate::sys::serial::println(b"[INIT] All services started, yielding for registration");
    for _ in 0..10 { crate::sched::yield_now(); }
    init_loop()
}

fn spawn_core_services() {
    for &name in CORE_SERVICES {
        crate::sys::serial::print(b"[INIT] Spawning: ");
        crate::sys::serial::println(name.as_bytes());
        spawn_svc(name, cap_for_service(name));
    }
}

fn spawn_driver_services() {
    for &name in DRIVER_SERVICES { spawn_svc(name, CAP_DRIVER); }
}

fn cap_for_service(name: &str) -> u64 {
    match name {
        "vfs" => CAP_VFS,
        "network" => CAP_NET,
        "display" => CAP_DISPLAY,
        "input" => CAP_INPUT,
        "crypto" => CAP_CRYPTO,
        "zk" => CAP_ZK,
        _ => 0,
    }
}

fn spawn_svc(name: &str, caps: u64) {
    match spawn_isolated_service(name, caps) {
        Ok(svc) => print_spawn_success(name, svc.pid, svc.asid),
        Err(_) => print_spawn_failure(name),
    }
}

fn print_spawn_success(name: &str, pid: u32, asid: u32) {
    crate::sys::serial::print(b"[INIT] Started ");
    crate::sys::serial::print(name.as_bytes());
    crate::sys::serial::print(b" pid=");
    crate::sys::serial::print_dec(pid as u64);
    crate::sys::serial::print(b" asid=");
    crate::sys::serial::print_dec(asid as u64);
    crate::sys::serial::println(b"");
}

fn print_spawn_failure(name: &str) {
    crate::sys::serial::print(b"[INIT] FAILED to start ");
    crate::sys::serial::println(name.as_bytes());
}
