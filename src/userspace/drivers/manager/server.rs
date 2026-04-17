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

use super::super::framework::DriverService;
use super::state::{DRIVERS, DriverState};
use super::dispatch::handle_request;

pub fn run_driver_manager() -> ! {
    init_drivers();
    crate::sys::boot_log::ok("DRIVERS", "Service ready");
    crate::sys::serial::println(b"[PROBE] drivers: before register_endpoint");
    crate::services::registry::register_endpoint_simple("drivers", 1006, 11);
    crate::sys::serial::println(b"[PROBE] drivers: after register_endpoint, entering server_loop");
    server_loop()
}

fn init_drivers() {
    let mut state = DriverState::new();
    let _ = state.pci.init();
    let _ = state.nvme.init();
    let _ = state.virtio.init();
    *DRIVERS.lock() = Some(state);
}

fn server_loop() -> ! {
    let mut tick: u32 = 0;
    crate::sys::serial::println(b"[PROBE] drivers: server_loop start, calling handle_drv_requests");
    loop {
        handle_drv_requests();
        if tick == 0 {
            crate::sys::serial::println(b"[PROBE] drivers: first handle_drv_requests returned, about to yield");
        }
        if tick == 0 {
            crate::sys::serial::println(b"[PROBE] drivers: about to format_tick");
        }
        if tick < 5 || tick.is_power_of_two() {
            let mut buf = [0u8; 40];
            let msg = format_tick(&mut buf, tick);
            crate::sys::serial::println(msg);
        }
        if tick == 0 {
            crate::sys::serial::println(b"[PROBE] drivers: post-format, incrementing tick");
        }
        tick = tick.wrapping_add(1);
        if tick == 1 {
            crate::sys::serial::println(b"[PROBE] drivers: calling yield_now first time");
        }
        crate::sched::yield_now();
        if tick == 1 {
            crate::sys::serial::println(b"[PROBE] drivers: first yield_now returned");
        }
    }
}

fn format_tick<'a>(buf: &'a mut [u8; 40], tick: u32) -> &'a [u8] {
    let prefix = b"[PROBE] drivers: server_loop tick=";
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut n = tick;
    let mut digits = [0u8; 10];
    let mut i = 0;
    if n == 0 {
        digits[0] = b'0';
        i = 1;
    } else {
        while n > 0 {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
        }
    }
    let mut pos = prefix.len();
    for j in (0..i).rev() {
        buf[pos] = digits[j];
        pos += 1;
    }
    &buf[..pos]
}

fn handle_drv_requests() {
    if let Some(msg) = crate::ipc::nonos_inbox::try_dequeue("drivers") {
        if let Some(req) = crate::services::server::parsing::parse_request(&msg.data) {
            let resp = handle_request(req);
            let data = crate::services::server::parsing::encode_response(&resp);
            if let Ok(reply) = crate::ipc::nonos_channel::IpcMessage::new("drivers", &msg.from, &data) {
                let _ = crate::ipc::nonos_inbox::try_enqueue(&msg.from, reply);
            }
        }
    }
}
