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

use super::super::service_list::CORE_SERVICES;
use crate::services::ServiceClient;

pub(super) fn verify_services() {
    crate::sys::serial::println(b"[INIT] Verifying service liveness...");
    for &name in CORE_SERVICES {
        match ServiceClient::connect(name) {
            Ok(client) => verify_client_ping(name, &client),
            Err(_) => print_not_registered(name),
        }
    }
}

fn verify_client_ping(name: &str, client: &ServiceClient) {
    match client.ping() {
        Ok(()) => {
            crate::sys::serial::print(b"[INIT] ");
            crate::sys::serial::print(name.as_bytes());
            crate::sys::serial::println(b" ALIVE");
        }
        Err(_) => {
            crate::sys::serial::print(b"[INIT] ");
            crate::sys::serial::print(name.as_bytes());
            crate::sys::serial::println(b" PING FAILED");
        }
    }
}

fn print_not_registered(name: &str) {
    crate::sys::serial::print(b"[INIT] ");
    crate::sys::serial::print(name.as_bytes());
    crate::sys::serial::println(b" NOT REGISTERED");
}
