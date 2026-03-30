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

pub fn run_net_service() -> ! {
    init_network_subsystem();
    crate::sys::boot_log::ok("NETWORK", "Service ready");
    crate::services::registry::register_endpoint_simple("network", 1003, 5);

    loop {
        handle_net_requests();
        crate::sched::yield_now();
    }
}

fn init_network_subsystem() {
    let _ = crate::sys::settings::network::load_from_disk();
    crate::sys::settings::network::init();
    crate::network::stack::init_network_stack();
    crate::network::manager::init();
    crate::entry::network::init_network();
}

fn handle_net_requests() {
    if let Some(msg) = crate::ipc::nonos_inbox::try_dequeue("network") {
        if let Some(req) = crate::services::server::parsing::parse_request(&msg.data) {
            let resp = handle_request(req);
            let data = crate::services::server::parsing::encode_response(&resp);
            if let Ok(reply) = crate::ipc::nonos_channel::IpcMessage::new("network", &msg.from, &data) {
                let _ = crate::ipc::nonos_inbox::try_enqueue(&msg.from, reply);
            }
        }
    }
}
