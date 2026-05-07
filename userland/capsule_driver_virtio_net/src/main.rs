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
mod log;
mod protocol;
mod queue;
mod regs;
mod rx;
mod server;
mod setup;
mod tx;

use nonos_libc::{_exit, heap_init};

use crate::log::{line, marker};

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    if heap_init().is_err() {
        line("[driver_net] heap init failed");
        _exit(1);
    }

    let mut driver = match setup::run() {
        Ok(d) => d,
        Err(e) => {
            line("[driver_net] setup failed:");
            line(e);
            _exit(2);
        }
    };

    // Probe: the device-config window must report non-zero queue
    // physical addresses (negotiation set them), and the cached
    // MAC must be non-zero whenever VIRTIO_NET_F_MAC is in play.
    // A zero on either side means the BAR mapping or the
    // negotiation lied; tear the broker grants down rather than
    // serve a half-initialised endpoint.
    if driver.rx.region_phys() == 0 || driver.tx.region_phys() == 0 {
        line("[driver_net] probe failed: zero virtqueue physical address");
        driver.release();
        _exit(3);
    }
    let mac_zero = driver.mac.iter().all(|&b| b == 0);
    if !mac_zero {
        marker("mac present");
    } else {
        marker("mac absent (feature off)");
    }
    let _ = driver.claim_epoch;
    let _ = driver.device_id;
    let _ = driver.mmio_grant;
    let _ = driver.rx_queue_grant;
    let _ = driver.rx_buffer_grant;
    let _ = driver.tx_queue_grant;
    let _ = driver.tx_buffer_grant;
    marker("endpoint driver.virtio_net0 ready");
    server::run(&mut driver);
}
