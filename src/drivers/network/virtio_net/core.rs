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

extern crate alloc;

use super::global::find_virtio_net_device;
use super::virtqueue::Virtqueue;
use crate::bus::pci::{enable_bus_master, enable_memory_space};
use crate::sys::serial;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;
use spin::Mutex;

pub struct VirtioNet {
    pub(super) io_base: u16,
    pub(super) mac: [u8; 6],
    pub(super) initialized: AtomicBool,
    pub(super) rx_queue: Mutex<Virtqueue>,
    pub(super) tx_queue: Mutex<Virtqueue>,
    pub(super) rx_packets: Mutex<Vec<Vec<u8>>>,
}

impl VirtioNet {
    pub fn new() -> Option<Self> {
        let dev = find_virtio_net_device()?;

        serial::print(b"[VIRTIO-NET] Found at ");
        serial::print_dec(dev.bus as u64);
        serial::print(b":");
        serial::print_dec(dev.device as u64);
        serial::println(b"");

        enable_bus_master(dev.bus, dev.device, dev.function);
        enable_memory_space(dev.bus, dev.device, dev.function);

        let io_base = (dev.bar0 & !0x3) as u16;
        if io_base == 0 {
            serial::println(b"[VIRTIO-NET] BAR0 is zero!");
            return None;
        }

        serial::print(b"[VIRTIO-NET] IO base: 0x");
        serial::print_hex(io_base as u64);
        serial::println(b"");

        Some(Self::create_uninit(io_base))
    }

    fn create_uninit(io_base: u16) -> Self {
        use super::descriptors::*;
        use core::ptr::addr_of_mut;

        Self {
            io_base,
            mac: [0; 6],
            initialized: AtomicBool::new(false),
            rx_queue: Mutex::new(Virtqueue::new(
                addr_of_mut!(RX_DESCS),
                addr_of_mut!(RX_AVAIL),
                addr_of_mut!(RX_USED),
            )),
            tx_queue: Mutex::new(Virtqueue::new(
                addr_of_mut!(TX_DESCS),
                addr_of_mut!(TX_AVAIL),
                addr_of_mut!(TX_USED),
            )),
            rx_packets: Mutex::new(Vec::new()),
        }
    }
}
