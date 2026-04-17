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
    crate::services::registry::register_endpoint_simple("drivers", 1006, 11);
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
    crate::sys::serial::println(b"[DRIVERS] Entering server loop");
    let mut tick = 0u32;
    loop {
        handle_drv_requests();
        tick = tick.wrapping_add(1);
        if tick == 1 || tick % 1000 == 0 {
            crate::sys::serial::print(b"[DRIVERS] loop ");
            crate::sys::serial::print_dec(tick as u64);
            crate::sys::serial::println(b"");
        }
        crate::sched::yield_now();
    }
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
