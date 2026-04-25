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
use core::ptr::addr_of;
use core::sync::atomic::Ordering;

use super::buffers::{RX_BUFFER, TX_BUFFERS};
use super::constants::*;
use super::core::Rtl8139;
use crate::network::stack::SmolDevice;
use crate::sys::io::{inw, outl, outw};

impl Rtl8139 {
    pub fn poll_rx(&self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        let isr = unsafe { inw(self.io_base + REG_ISR) };
        if isr & ISR_ROK == 0 {
            return;
        }
        unsafe { outw(self.io_base + REG_ISR, ISR_ROK) };

        let mut offset = self.rx_offset.load(Ordering::SeqCst) as usize;
        let cbr = unsafe { inw(self.io_base + REG_CBR) } as usize;

        while offset != cbr {
            let header = unsafe {
                let p = addr_of!(RX_BUFFER).cast::<u8>().add(offset);
                u32::from_le_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
            };

            if header & 0x01 == 0 {
                break;
            }
            let len = ((header >> 16) & 0xFFFF) as usize;
            if len < 4 || len > 1518 {
                break;
            }

            let data_offset = (offset + 4) % (RX_BUF_SIZE - 16);
            let pkt_len = len - 4;
            let mut pkt = Vec::with_capacity(pkt_len);

            unsafe {
                let base = addr_of!(RX_BUFFER).cast::<u8>();
                for i in 0..pkt_len {
                    pkt.push(*base.add((data_offset + i) % (RX_BUF_SIZE - 16)));
                }
            }
            self.rx_queue.lock().push(pkt);

            offset = (offset + len + 4 + 3) & !3;
            if offset >= RX_BUF_SIZE - 16 {
                offset -= RX_BUF_SIZE - 16;
            }
        }

        self.rx_offset.store(offset as u32, Ordering::SeqCst);
        unsafe { outw(self.io_base + REG_CAPR, (offset as u16).wrapping_sub(16)) };
    }

    pub fn transmit(&self, data: &[u8]) -> Result<(), ()> {
        if !self.initialized.load(Ordering::SeqCst) || data.len() > TX_BUF_SIZE {
            return Err(());
        }

        let cur = (self.tx_cur.fetch_add(1, Ordering::SeqCst) % NUM_TX_BUFFERS as u32) as usize;

        unsafe {
            let buf = &mut TX_BUFFERS[cur].data[..data.len()];
            buf.copy_from_slice(data);
            outl(self.io_base + REG_TXSTATUS0 + (cur as u16 * 4), data.len() as u32);
        }
        Ok(())
    }

    pub fn recv(&self) -> Option<Vec<u8>> {
        self.poll_rx();
        self.rx_queue.lock().pop()
    }
}

impl SmolDevice for Rtl8139 {
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
