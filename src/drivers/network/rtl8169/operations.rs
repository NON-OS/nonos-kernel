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
use super::core::Rtl8169;
use super::descriptors::*;
use crate::network::stack::SmolDevice;

impl Rtl8169 {
    pub fn poll_rx(&self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        let isr = self.read16(REG_ISR);
        if isr & ISR_ROK != 0 {
            self.write16(REG_ISR, ISR_ROK);
        }

        let mut cur = self.rx_cur.load(Ordering::SeqCst) as usize;

        unsafe {
            while RX_RING.descs[cur].opts1 & DESC_OWN == 0 {
                let opts = RX_RING.descs[cur].opts1;
                let len = (opts & 0x3FFF) as usize;

                if len > 4 && len <= BUFFER_SIZE {
                    let pkt_len = len - 4;
                    let mut pkt = Vec::with_capacity(pkt_len);
                    pkt.extend_from_slice(&RX_BUFFERS[cur][..pkt_len]);
                    self.rx_queue.lock().push(pkt);
                }

                let is_last = cur == NUM_RX_DESC - 1;
                RX_RING.descs[cur].opts1 =
                    DESC_OWN | (BUFFER_SIZE as u32) | if is_last { DESC_EOR } else { 0 };

                cur = (cur + 1) % NUM_RX_DESC;
            }
        }

        self.rx_cur.store(cur as u32, Ordering::SeqCst);
    }

    pub fn transmit(&self, data: &[u8]) -> Result<(), ()> {
        if !self.initialized.load(Ordering::SeqCst) || data.len() > BUFFER_SIZE {
            return Err(());
        }

        let cur = self.tx_cur.load(Ordering::SeqCst) as usize;

        unsafe {
            if TX_RING.descs[cur].opts1 & DESC_OWN != 0 {
                return Err(());
            }

            TX_BUFFERS[cur][..data.len()].copy_from_slice(data);

            let is_last = cur == NUM_TX_DESC - 1;
            TX_RING.descs[cur].opts1 = DESC_OWN
                | DESC_FS
                | DESC_LS
                | (data.len() as u32)
                | if is_last { DESC_EOR } else { 0 };
        }

        self.tx_cur.store(((cur + 1) % NUM_TX_DESC) as u32, Ordering::SeqCst);
        self.write8(REG_TX_POLL, TX_POLL_HPQ);
        Ok(())
    }

    pub fn recv(&self) -> Option<Vec<u8>> {
        self.poll_rx();
        self.rx_queue.lock().pop()
    }
}

impl SmolDevice for Rtl8169 {
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
