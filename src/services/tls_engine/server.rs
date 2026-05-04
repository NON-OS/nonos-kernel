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

use super::dispatch;

pub fn run_tls_service() -> ! {
    crate::services::registry::register_endpoint_simple("tls", 1036, 36);
    crate::sys::boot_log::ok("TLS", "Service ready");

    loop {
        handle_requests();
        crate::sched::yield_now();
    }
}

fn handle_requests() {
    if let Some(msg) = crate::ipc::nonos_inbox::try_dequeue("tls") {
        let response = dispatch::process_request(&msg.data);
        if let Ok(reply) = crate::ipc::nonos_channel::IpcMessage::new("tls", &msg.from, &response) {
            let _ = crate::ipc::nonos_inbox::try_enqueue(&msg.from, reply);
        }
    }
}
