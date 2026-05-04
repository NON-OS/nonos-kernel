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

use super::dispatch::handle_request;

pub fn run_input_service() -> ! {
    init_input_subsystem();
    crate::services::registry::register_endpoint_simple("input", 1002, 4);
    crate::sys::serial::println(b"[INPUT] phase=ready");
    crate::sys::boot_log::ok("INPUT", "Service ready");

    loop {
        handle_input_requests();
        crate::sched::yield_now();
    }
}

fn init_input_subsystem() {
    let _ = crate::input::i2c_hid::init();
    crate::sys::serial::println(b"[INPUT] phase=i2c_hid done");
    crate::sched::yield_now();
    crate::input::usb_hid::init();
    crate::sys::serial::println(b"[INPUT] phase=usb_hid done");
    crate::sched::yield_now();
}

fn handle_input_requests() {
    if let Some(msg) = crate::ipc::nonos_inbox::try_dequeue("input") {
        if let Some(req) = crate::services::server::parsing::parse_request(&msg.data) {
            let resp = handle_request(req);
            let data = crate::services::server::parsing::encode_response(&resp);
            if let Ok(reply) = crate::ipc::nonos_channel::IpcMessage::new("input", &msg.from, &data)
            {
                let _ = crate::ipc::nonos_inbox::try_enqueue(&msg.from, reply);
            }
        }
    }
}
