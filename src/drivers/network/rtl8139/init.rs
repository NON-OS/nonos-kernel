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

use core::ptr::addr_of;
use core::sync::atomic::Ordering;

use super::buffers::{RX_BUFFER, TX_BUFFERS};
use super::constants::*;
use super::core::Rtl8139;
use crate::sys::io::{inb, outb, outl, outw};
use crate::sys::serial;

impl Rtl8139 {
    pub fn init(&mut self) -> Result<(), &'static str> {
        serial::println(b"[RTL8139] Initializing...");

        unsafe { outb(self.io_base + REG_CONFIG1, 0x00) };

        unsafe { outb(self.io_base + REG_CMD, CMD_RESET) };
        for _ in 0..100000 {
            if unsafe { inb(self.io_base + REG_CMD) } & CMD_RESET == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        self.read_mac();

        let rx_addr = addr_of!(RX_BUFFER) as u64;
        unsafe { outl(self.io_base + REG_RXBUF, rx_addr as u32) };

        for i in 0..NUM_TX_BUFFERS {
            let tx_addr = unsafe { addr_of!(TX_BUFFERS[i]) as u64 };
            unsafe { outl(self.io_base + REG_TXADDR0 + (i as u16 * 4), tx_addr as u32) };
        }

        unsafe { outw(self.io_base + REG_IMR, ISR_ROK | ISR_TOK) };
        unsafe {
            outl(
                self.io_base + REG_RCR,
                RCR_ACCEPT_ALL | RCR_WRAP | RCR_MXDMA_UNLIM | RCR_RBLEN_64K,
            )
        };
        unsafe { outl(self.io_base + REG_TCR, TCR_IFG_STANDARD | TCR_MXDMA_2048) };
        unsafe { outb(self.io_base + REG_CMD, CMD_RX_ENABLE | CMD_TX_ENABLE) };

        self.initialized.store(true, Ordering::SeqCst);
        serial::println(b"[RTL8139] Initialized successfully!");
        Ok(())
    }

    fn read_mac(&mut self) {
        for i in 0..6 {
            self.mac[i] = unsafe { inb(self.io_base + REG_MAC0 + i as u16) };
        }
        serial::print(b"[RTL8139] MAC: ");
        for (i, &b) in self.mac.iter().enumerate() {
            if i > 0 {
                serial::print(b":");
            }
            serial::print_hex(b as u64);
        }
        serial::println(b"");
    }
}
