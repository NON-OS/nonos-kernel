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
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::Ordering;

use super::constants::*;
use super::core::E1000;
use super::descriptors::{RxDesc, TxDesc, STATIC_RX_BUFS, STATIC_RX_DESCS};
use super::descriptors::{STATIC_TX_BUFS, STATIC_TX_DESCS};
use crate::network::stack::SmolDevice;

impl E1000 {
    pub fn poll_rx(&self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        let mut cur = self.rx_cur.load(Ordering::SeqCst) as usize;

        // SAFETY: Accessing static DMA buffers, single-threaded NIC access via atomic guards
        unsafe {
            let rx_descs = addr_of_mut!(STATIC_RX_DESCS) as *mut [RxDesc; NUM_RX_DESC];
            let rx_bufs = addr_of!(STATIC_RX_BUFS) as *const [[u8; RX_BUFFER_SIZE]; NUM_RX_DESC];

            while ((*rx_descs)[cur].status & DESC_DD) != 0 {
                let length = (*rx_descs)[cur].length as usize;

                if length > 0 && length <= RX_BUFFER_SIZE {
                    let mut packet = Vec::with_capacity(length);
                    packet.extend_from_slice(&(&(*rx_bufs)[cur])[..length]);
                    self.rx_queue.lock().push(packet);
                }

                (*rx_descs)[cur].status = 0;
                self.write_reg(REG_RDT, cur as u32);
                cur = (cur + 1) % NUM_RX_DESC;
            }
        }

        self.rx_cur.store(cur as u32, Ordering::SeqCst);
    }

    pub fn transmit(&self, data: &[u8]) -> Result<(), ()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(());
        }

        if data.len() > RX_BUFFER_SIZE {
            return Err(());
        }

        let cur = self.tx_cur.load(Ordering::SeqCst) as usize;

        // SAFETY: Accessing static DMA buffers, single-threaded NIC access via atomic guards
        unsafe {
            let tx_descs = addr_of_mut!(STATIC_TX_DESCS) as *mut [TxDesc; NUM_TX_DESC];
            let tx_bufs = addr_of_mut!(STATIC_TX_BUFS) as *mut [[u8; RX_BUFFER_SIZE]; NUM_TX_DESC];

            while ((*tx_descs)[cur].status & DESC_DD) == 0 {
                core::hint::spin_loop();
            }

            let buf_ptr = (*tx_bufs)[cur].as_mut_ptr();
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());

            (*tx_descs)[cur].length = data.len() as u16;
            (*tx_descs)[cur].cmd = DESC_CMD_EOP | DESC_CMD_IFCS | DESC_CMD_RS;
            (*tx_descs)[cur].status = 0;
        }

        let next = ((cur + 1) % NUM_TX_DESC) as u32;
        self.tx_cur.store(next, Ordering::SeqCst);
        self.write_reg(REG_TDT, next);

        Ok(())
    }

    pub fn recv(&self) -> Option<Vec<u8>> {
        self.poll_rx();
        self.rx_queue.lock().pop()
    }
}

impl SmolDevice for E1000 {
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
