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
mod fill;
mod init;
mod log;
mod protocol;
mod queue;
mod regs;
mod server;
mod setup;

use nonos_libc::{_exit, heap_init};

use crate::log::{line, marker};

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    if heap_init().is_err() {
        line("[driver_rng] heap init failed");
        _exit(1);
    }

    let mut driver = match setup::run() {
        Ok(d) => d,
        Err(e) => {
            line("[driver_rng] setup failed:");
            line(e);
            _exit(2);
        }
    };

    // Sanity check: pull one fill before opening the service.
    // A device that fails the first round trip is not worth
    // exposing as an entropy source.
    match crate::fill::fill(driver.regs, &mut driver.queue, driver.irq_grant) {
        Ok(n) => {
            let bytes = driver.queue.buffer(n);
            let mut nz = 0usize;
            for &b in bytes.iter() {
                if b != 0 {
                    nz += 1;
                }
            }
            if nz == 0 {
                line("[driver_rng] entropy buffer all zero on probe");
                driver.release();
                _exit(4);
            }
        }
        Err(e) => {
            line("[driver_rng] probe fill failed:");
            line(e);
            driver.release();
            _exit(3);
        }
    }

    let _ = driver.queue.region_phys();
    let _ = driver.claim_epoch;
    marker("ready");
    server::run(&mut driver);
}
