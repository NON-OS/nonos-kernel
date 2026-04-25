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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::constants::*;
use super::core::VirtioNet;
use super::descriptors::{VirtioNetHdr, RX_BUFFERS, RX_DESCS, RX_USED, TX_BUFFERS};
use crate::network::stack::SmolDevice;

impl VirtioNet {
    pub fn poll_rx(&self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        let mut rx = self.rx_queue.lock();
        unsafe {
            while rx.has_used() {
                let used_idx = rx.last_used_idx as usize % QUEUE_SIZE;
                let elem = RX_USED.ring[used_idx];
                let desc_idx = elem.id as usize;
                let len = elem.len as usize;

                if len > core::mem::size_of::<VirtioNetHdr>() {
                    let hdr_size = core::mem::size_of::<VirtioNetHdr>();
                    let data_len = len - hdr_size;
                    let buf = &RX_BUFFERS[desc_idx][hdr_size..hdr_size + data_len];
                    let mut pkt = Vec::with_capacity(data_len);
                    pkt.extend_from_slice(buf);
                    self.rx_packets.lock().push(pkt);
                }

                RX_DESCS[desc_idx].len = BUFFER_SIZE as u32;
                RX_DESCS[desc_idx].flags = VRING_DESC_F_WRITE;
                rx.add_buffer(desc_idx as u16);
                rx.last_used_idx = rx.last_used_idx.wrapping_add(1);
            }
        }
    }

    pub fn transmit(&self, data: &[u8]) -> Result<(), ()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(());
        }

        let hdr_size = core::mem::size_of::<VirtioNetHdr>();
        if data.len() + hdr_size > BUFFER_SIZE {
            return Err(());
        }

        let mut tx = self.tx_queue.lock();
        let desc_idx = unsafe { tx.alloc_desc().ok_or(())? };

        unsafe {
            let buf = &mut TX_BUFFERS[desc_idx as usize];
            buf[..hdr_size].fill(0);
            buf[hdr_size..hdr_size + data.len()].copy_from_slice(data);

            super::descriptors::TX_DESCS[desc_idx as usize].addr = buf.as_ptr() as u64;
            super::descriptors::TX_DESCS[desc_idx as usize].len = (hdr_size + data.len()) as u32;
            super::descriptors::TX_DESCS[desc_idx as usize].flags = 0;

            tx.add_buffer(desc_idx);
        }

        self.notify_queue(VIRTQ_TX);
        Ok(())
    }

    pub fn recv(&self) -> Option<Vec<u8>> {
        self.poll_rx();
        self.rx_packets.lock().pop()
    }
}

impl SmolDevice for VirtioNet {
    fn now_ms(&self) -> u64 {
        crate::time::timestamp_millis()
    }
    fn recv(&self) -> Option<Vec<u8>> {
        self.recv()
    }
    fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        self.transmit(frame)
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
}
