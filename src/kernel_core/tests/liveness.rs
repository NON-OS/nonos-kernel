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

use crate::services::ServiceClient;

const CORE_SERVICES: [&str; 6] = ["vfs", "network", "display", "input", "crypto", "zk"];

pub fn validate_service_liveness() -> bool {
    let mut all_ok = true;

    for name in &CORE_SERVICES {
        all_ok &= check_service(name);
    }

    all_ok
}

fn check_service(name: &str) -> bool {
    match ServiceClient::connect(name) {
        Ok(client) => match client.ping() {
            Ok(()) => {
                log_service_status(name, b"ALIVE");
                true
            }
            Err(_) => {
                log_service_status(name, b"PING FAIL");
                false
            }
        },
        Err(_) => {
            log_service_status(name, b"NOT FOUND");
            false
        }
    }
}

fn log_service_status(name: &str, status: &[u8]) {
    crate::sys::serial::print(b"[VALIDATE] ");
    crate::sys::serial::print(name.as_bytes());
    crate::sys::serial::print(b" ");
    crate::sys::serial::println(status);
}
