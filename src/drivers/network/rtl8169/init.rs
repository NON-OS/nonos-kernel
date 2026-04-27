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
use super::core::Rtl8169;
use super::descriptors::*;
use crate::sys::serial;

impl Rtl8169 {
    pub fn init(&mut self) -> Result<(), &'static str> {
        serial::println(b"[RTL8169] Initializing...");

        self.write8(REG_CMD, CMD_RESET);
        for _ in 0..100000 {
            if self.read8(REG_CMD) & CMD_RESET == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        self.read_mac();
        self.init_rx_ring();
        self.init_tx_ring();

        self.write16(REG_RMS as u32, BUFFER_SIZE as u16);

        let rx_addr = addr_of_mut!(RX_RING) as u64;
        self.write32(REG_RXDESC_ADDR_LO, rx_addr as u32);
        self.write32(REG_RXDESC_ADDR_HI, (rx_addr >> 32) as u32);

        let tx_addr = addr_of_mut!(TX_RING) as u64;
        self.write32(REG_TXDESC_ADDR_LO, tx_addr as u32);
        self.write32(REG_TXDESC_ADDR_HI, (tx_addr >> 32) as u32);

        self.write32(REG_RX_CONFIG, RX_CONFIG_ACCEPT_ALL | RX_CONFIG_DMA | RX_CONFIG_MAXDMA);
        self.write32(REG_TX_CONFIG, TX_CONFIG_IFG | TX_CONFIG_DMA);
        self.write16(REG_IMR, ISR_ROK | ISR_TOK);
        self.write8(REG_CMD, CMD_RX_ENABLE | CMD_TX_ENABLE);

        self.initialized.store(true, Ordering::SeqCst);
        serial::println(b"[RTL8169] Initialized successfully!");
        Ok(())
    }

    fn read_mac(&mut self) {
        for i in 0..6 {
            self.mac[i] = self.read8(REG_MAC0 + i as u32);
        }
        serial::print(b"[RTL8169] MAC: ");
        for (i, &b) in self.mac.iter().enumerate() {
            if i > 0 {
                serial::print(b":");
            }
            serial::print_hex(b as u64);
        }
        serial::println(b"");
    }

    fn init_rx_ring(&mut self) {
        unsafe {
            for i in 0..NUM_RX_DESC {
                let buf_addr = RX_BUFFERS[i].as_ptr() as u64;
                let is_last = i == NUM_RX_DESC - 1;
                RX_RING.descs[i].opts1 =
                    DESC_OWN | (BUFFER_SIZE as u32) | if is_last { DESC_EOR } else { 0 };
                RX_RING.descs[i].addr_lo = buf_addr as u32;
                RX_RING.descs[i].addr_hi = (buf_addr >> 32) as u32;
            }
        }
    }

    fn init_tx_ring(&mut self) {
        unsafe {
            for i in 0..NUM_TX_DESC {
                let buf_addr = TX_BUFFERS[i].as_ptr() as u64;
                let is_last = i == NUM_TX_DESC - 1;
                TX_RING.descs[i].opts1 = if is_last { DESC_EOR } else { 0 };
                TX_RING.descs[i].addr_lo = buf_addr as u32;
                TX_RING.descs[i].addr_hi = (buf_addr >> 32) as u32;
            }
        }
    }
}
