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
    crate::sys::serial::println(b"[PROBE] init: after spawn_driver_services, entering yield loop (50x)");
    for i in 0..50 {
        if i == 0 || i == 1 || i == 5 || i == 10 || i == 25 || i == 49 {
            let mut buf = [0u8; 32];
            let msg = fmt_yield(&mut buf, b"drv", i);
            crate::sys::serial::println(msg);
        }
        crate::sched::yield_now();
    }
    crate::sys::serial::println(b"[PROBE] init: drivers yield loop done, spawning KERNEL_SERVICES");
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

fn fmt_yield<'a>(buf: &'a mut [u8; 32], tag: &[u8], i: u32) -> &'a [u8] {
    let prefix = b"[PROBE] init: yield ";
    let mut pos = 0;
    buf[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    buf[pos..pos + tag.len()].copy_from_slice(tag);
    pos += tag.len();
    buf[pos] = b' ';
    pos += 1;
    let mut n = i;
    let mut digits = [0u8; 10];
    let mut di = 0;
    if n == 0 { digits[0] = b'0'; di = 1; }
    else { while n > 0 { digits[di] = b'0' + (n % 10) as u8; n /= 10; di += 1; } }
    for j in (0..di).rev() { buf[pos] = digits[j]; pos += 1; }
    &buf[..pos]
}

fn lower_init_priority() {
    use crate::process::core::{Priority, PROCESS_TABLE, CURRENT_PID};
    use core::sync::atomic::Ordering;
    let pid = CURRENT_PID.load(Ordering::Relaxed);
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.priority.lock() = Priority::Low;
    }
}
