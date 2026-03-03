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

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::Ordering;

use super::constants::*;
use super::core::E1000;
use super::descriptors::{RxDesc, TxDesc, STATIC_RX_BUFS, STATIC_RX_DESCS};
use super::descriptors::{STATIC_TX_BUFS, STATIC_TX_DESCS};
use crate::sys::serial;

impl E1000 {
    pub fn init(&mut self) -> Result<(), &'static str> {
        serial::println(b"[E1000] Initializing...");

        self.write_reg(REG_CTRL, CTRL_RST);
        for _ in 0..10000 {
            core::hint::spin_loop();
        }

        while self.read_reg(REG_CTRL) & CTRL_RST != 0 {
            core::hint::spin_loop();
        }

        self.write_reg(REG_IMC, 0xFFFFFFFF);
        self.read_reg(REG_ICR);

        self.read_mac();

        let ctrl = self.read_reg(REG_CTRL);
        self.write_reg(REG_CTRL, ctrl | CTRL_SLU);

        self.init_rx()?;
        self.init_tx()?;

        self.write_reg(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC);
        self.write_reg(
            REG_TCTL,
            TCTL_EN | TCTL_PSP | (15 << TCTL_CT_SHIFT) | (64 << TCTL_COLD_SHIFT),
        );

        self.initialized.store(true, Ordering::SeqCst);

        serial::println(b"[E1000] Initialized successfully!");
        Ok(())
    }

    fn init_rx(&mut self) -> Result<(), &'static str> {
        // SAFETY: Single-threaded initialization, hardware requires static DMA buffers
        unsafe {
            let rx_bufs = addr_of!(STATIC_RX_BUFS) as *const [[u8; RX_BUFFER_SIZE]; NUM_RX_DESC];
            let rx_descs = addr_of_mut!(STATIC_RX_DESCS) as *mut [RxDesc; NUM_RX_DESC];

            for i in 0..NUM_RX_DESC {
                let buf_addr = (*rx_bufs)[i].as_ptr() as u64;
                (*rx_descs)[i].addr = buf_addr;
                (*rx_descs)[i].status = 0;
            }

            let desc_addr = rx_descs as u64;

            self.write_reg(REG_RDBAL, desc_addr as u32);
            self.write_reg(REG_RDBAH, (desc_addr >> 32) as u32);
            self.write_reg(
                REG_RDLEN,
                (NUM_RX_DESC * core::mem::size_of::<RxDesc>()) as u32,
            );
            self.write_reg(REG_RDH, 0);
            self.write_reg(REG_RDT, (NUM_RX_DESC - 1) as u32);
        }

        self.rx_cur.store(0, Ordering::SeqCst);

        serial::println(b"[E1000] RX ring initialized");
        Ok(())
    }

    fn init_tx(&mut self) -> Result<(), &'static str> {
        // SAFETY: Single-threaded initialization, hardware requires static DMA buffers
        unsafe {
            let tx_bufs = addr_of!(STATIC_TX_BUFS) as *const [[u8; RX_BUFFER_SIZE]; NUM_TX_DESC];
            let tx_descs = addr_of_mut!(STATIC_TX_DESCS) as *mut [TxDesc; NUM_TX_DESC];

            for i in 0..NUM_TX_DESC {
                let buf_addr = (*tx_bufs)[i].as_ptr() as u64;
                (*tx_descs)[i].addr = buf_addr;
                (*tx_descs)[i].status = DESC_DD;
                (*tx_descs)[i].cmd = 0;
            }

            let desc_addr = tx_descs as u64;

            self.write_reg(REG_TDBAL, desc_addr as u32);
            self.write_reg(REG_TDBAH, (desc_addr >> 32) as u32);
            self.write_reg(
                REG_TDLEN,
                (NUM_TX_DESC * core::mem::size_of::<TxDesc>()) as u32,
            );
            self.write_reg(REG_TDH, 0);
            self.write_reg(REG_TDT, 0);
        }

        self.tx_cur.store(0, Ordering::SeqCst);

        serial::println(b"[E1000] TX ring initialized");
        Ok(())
    }
}
