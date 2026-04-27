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

use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;

use super::constants::*;
use super::core::VirtioNet;
use super::descriptors::*;
use crate::sys::io::{inb, inl, outb, outl, outw};
use crate::sys::serial;

impl VirtioNet {
    pub fn init(&mut self) -> Result<(), &'static str> {
        serial::println(b"[VIRTIO-NET] Initializing...");

        self.write_status(0);
        self.write_status(VIRTIO_STATUS_ACKNOWLEDGE);
        self.write_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

        let features = self.read_features();
        let supported = features & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
        self.write_features(supported);

        self.write_status(
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
        );

        self.read_mac();
        self.init_rx_queue()?;
        self.init_tx_queue()?;

        self.write_status(
            VIRTIO_STATUS_ACKNOWLEDGE
                | VIRTIO_STATUS_DRIVER
                | VIRTIO_STATUS_FEATURES_OK
                | VIRTIO_STATUS_DRIVER_OK,
        );
        self.initialized.store(true, Ordering::SeqCst);

        serial::println(b"[VIRTIO-NET] Initialized successfully!");
        Ok(())
    }

    pub(super) fn read_features(&self) -> u32 {
        unsafe { inl(self.io_base + REG_DEVICE_FEATURES as u16) }
    }
    pub(super) fn write_features(&self, f: u32) {
        unsafe { outl(self.io_base + REG_DRIVER_FEATURES as u16, f) }
    }
    pub(super) fn write_status(&self, s: u8) {
        unsafe { outb(self.io_base + REG_DEVICE_STATUS as u16, s) }
    }
    pub(super) fn select_queue(&self, q: u16) {
        unsafe { outw(self.io_base + REG_QUEUE_SELECT as u16, q) }
    }
    pub(super) fn write_queue_addr(&self, a: u32) {
        unsafe { outl(self.io_base + REG_QUEUE_ADDRESS as u16, a) }
    }
    pub(super) fn notify_queue(&self, q: u16) {
        unsafe { outw(self.io_base + REG_QUEUE_NOTIFY as u16, q) }
    }

    pub(super) fn read_mac(&mut self) {
        for i in 0..6 {
            self.mac[i] = unsafe { inb(self.io_base + REG_MAC_BASE as u16 + i as u16) };
        }
        serial::print(b"[VIRTIO-NET] MAC: ");
        for (i, &b) in self.mac.iter().enumerate() {
            if i > 0 {
                serial::print(b":");
            }
            serial::print_hex(b as u64);
        }
        serial::println(b"");
    }

    fn init_rx_queue(&mut self) -> Result<(), &'static str> {
        self.select_queue(VIRTQ_RX);
        unsafe {
            let mut rx = self.rx_queue.lock();
            rx.setup_free_list();
            for i in 0..QUEUE_SIZE {
                RX_DESCS[i].addr = RX_BUFFERS[i].as_ptr() as u64;
                RX_DESCS[i].len = BUFFER_SIZE as u32;
                RX_DESCS[i].flags = VRING_DESC_F_WRITE;
                rx.add_buffer(i as u16);
            }
            rx.num_free = 0;
        }
        self.write_queue_addr(addr_of_mut!(RX_DESCS) as u64 as u32 / 4096);
        serial::println(b"[VIRTIO-NET] RX queue initialized");
        Ok(())
    }

    fn init_tx_queue(&mut self) -> Result<(), &'static str> {
        self.select_queue(VIRTQ_TX);
        unsafe {
            self.tx_queue.lock().setup_free_list();
        }
        self.write_queue_addr(addr_of_mut!(TX_DESCS) as u64 as u32 / 4096);
        serial::println(b"[VIRTIO-NET] TX queue initialized");
        Ok(())
    }
}
