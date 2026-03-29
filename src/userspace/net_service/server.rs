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

use crate::services::ServiceServer;
use super::dispatch::handle_request;

const NET_CAP: u64 = 0x0002;

pub fn run_net_service() -> ! {
    crate::sys::serial::println(b"[NET] Network service starting");
    init_network_subsystem();
    crate::sys::serial::println(b"[NET] Network subsystem initialized");

    let server = match ServiceServer::new("network", NET_CAP) {
        Ok(s) => s,
        Err(_) => {
            crate::sys::serial::println(b"[NET] Failed to create server");
            loop { crate::sched::yield_now(); }
        }
    };

    crate::sys::serial::println(b"[NET] Network server ready");

    loop {
        server.poll_once(&mut handle_request);
        crate::sched::yield_now();
    }
}

fn init_network_subsystem() {
    crate::network::stack::init_network_stack();
    crate::network::manager::init();
}
