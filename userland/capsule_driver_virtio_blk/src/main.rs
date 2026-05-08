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
mod discover;
mod init;
mod io;
mod protocol;
mod queue;
mod regs;
mod server;
mod setup;

use nonos_libc::{_exit, heap_init};


#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    if heap_init().is_err() {
        _exit(1);
    }

    let mut driver = match setup::run() {
        Ok(d) => d,
        Err(e) => {
            _exit(2);
        }
    };

    // Probe the device with a flush before opening the service.
    // The flush touches the descriptor chain and the used ring,
    // so it surfaces a broken queue / IRQ wiring without consuming
    // a real read. A device that does not advertise FLUSH still
    // gets a UNSUPP back which is fine — the queue plumbing is
    // what we are exercising here.
    match crate::io::submit(
        driver.regs,
        &mut driver.queue,
        driver.irq_grant,
        crate::queue::Direction::Flush,
        0,
        0,
    ) {
        Ok(()) | Err(crate::io::BlkError::Unsupported) => {}
        Err(_) => {
            driver.release();
            _exit(3);
        }
    }

    let _ = driver.queue.region_phys();
    let _ = driver.claim_epoch;
    let _ = driver.flush_supported;
    server::run(&mut driver);
}
