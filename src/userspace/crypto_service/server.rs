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

use crate::services::{ServiceServer, CAP_CRYPTO};
use super::dispatch::handle_request;

pub fn run_crypto_service() -> ! {
    crate::sys::serial::println(b"[CRYPTO] Crypto service starting");

    let server = match ServiceServer::new("crypto", CAP_CRYPTO) {
        Ok(s) => s,
        Err(_) => {
            crate::sys::serial::println(b"[CRYPTO] Failed to create server");
            loop { crate::sched::yield_now(); }
        }
    };

    crate::sys::serial::println(b"[CRYPTO] Crypto server ready");

    loop {
        server.poll_once(&mut handle_request);
        crate::sched::yield_now();
    }
}
