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
use crate::services::caps::CAP_DRIVER;
use super::super::framework::DriverService;
use super::state::{DRIVERS, DriverState};
use super::dispatch::handle_request;

pub fn run_driver_manager() -> ! {
    crate::sys::serial::println(b"[DRV] Driver manager starting");
    init_drivers();
    let server = match ServiceServer::new("drivers", CAP_DRIVER) {
        Ok(s) => s,
        Err(_) => {
            crate::sys::serial::println(b"[DRV] Failed to create server");
            loop { crate::sched::yield_now(); }
        }
    };
    crate::sys::serial::println(b"[DRV] Driver manager ready");
    server_loop(&server)
}

fn init_drivers() {
    let mut state = DriverState::new();
    let _ = state.pci.init();
    let _ = state.nvme.init();
    let _ = state.virtio.init();
    *DRIVERS.lock() = Some(state);
}

fn server_loop(server: &ServiceServer) -> ! {
    loop {
        server.poll_once(&mut |req| handle_request(req));
        crate::sched::yield_now();
    }
}
