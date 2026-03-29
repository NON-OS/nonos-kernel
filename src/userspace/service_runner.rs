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

use super::{
    run_vfs_service, run_net_service, run_display_service, run_driver_manager,
    run_crypto_service, run_zk_service, run_input_service,
};

pub fn run_service_by_name(name: &str) -> ! {
    match name {
        "vfs" => run_vfs_service(),
        "network" => run_net_service(),
        "display" => run_display_service(),
        "drivers" => run_driver_manager(),
        "crypto" => run_crypto_service(),
        "zk" => run_zk_service(),
        "input" => run_input_service(),
        _ => {
            crate::sys::serial::print(b"[SVC] Unknown service: ");
            crate::sys::serial::println(name.as_bytes());
            loop { crate::sched::yield_now(); }
        }
    }
}

pub fn start_service_process(name: &str) {
    crate::sys::serial::print(b"[SVC] Starting service process: ");
    crate::sys::serial::println(name.as_bytes());
}
