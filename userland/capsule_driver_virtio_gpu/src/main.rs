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

#![no_std]
#![no_main]

extern crate alloc;

mod constants;
mod debug;
mod device;
mod discover;
mod driver;
mod init;
mod protocol;
mod regs;
mod server;
mod setup;
mod state;

use nonos_libc::{heap_init, mk_exit};

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    debug::marker(b"boot");
    if heap_init().is_err() {
        debug::marker(b"heap init failed");
        mk_exit(1);
    }
    let driver = match setup::run() {
        Ok(driver) => driver,
        Err(err) => {
            debug::marker(err.as_bytes());
            mk_exit(2);
        }
    };
    debug::marker(b"setup complete");
    server::run(driver);
}
