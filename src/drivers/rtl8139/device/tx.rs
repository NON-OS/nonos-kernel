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

use core::sync::atomic::Ordering;

use super::core::Rtl8139Device;
use crate::drivers::rtl8139::constants::{
    reg, tcr, tsd, MIN_FRAME_SIZE, TX_BUFFER_SIZE, TX_DESC_COUNT,
};
use crate::drivers::rtl8139::io::{inl, outl};

impl Rtl8139Device {
    pub(crate) fn init_tx(&self) {
        outl(self.io_base + reg::TSAD0, self.tx_buffers_phys[0].as_u64() as u32);
        outl(self.io_base + reg::TSAD1, self.tx_buffers_phys[1].as_u64() as u32);
        outl(self.io_base + reg::TSAD2, self.tx_buffers_phys[2].as_u64() as u32);
        outl(self.io_base + reg::TSAD3, self.tx_buffers_phys[3].as_u64() as u32);

        let tcr_val = tcr::MXDMA_256 | tcr::IFG_STD;
        outl(self.io_base + reg::TCR, tcr_val);
    }

    pub fn transmit(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > TX_BUFFER_SIZE {
            return Err("Packet too large");
        }
        if data.len() < MIN_FRAME_SIZE {
            return Err("Packet too small");
        }

        let desc = self.tx_cur;
        let tsd_reg = match desc {
            0 => reg::TSD0,
            1 => reg::TSD1,
            2 => reg::TSD2,
            3 => reg::TSD3,
            _ => return Err("Invalid TX descriptor"),
        };

        let tsd_val = inl(self.io_base + tsd_reg);
        if tsd_val & tsd::OWN != 0 {
            return Err("TX descriptor busy");
        }

        // SAFETY: tx_buffers_virt[desc] points to valid DMA memory of TX_BUFFER_SIZE bytes
        unsafe {
            let buf_ptr = self.tx_buffers_virt[desc].as_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());
        }

        let new_tsd = (data.len() as u32) & 0x1FFF;
        outl(self.io_base + tsd_reg, new_tsd);

        self.tx_cur = (self.tx_cur + 1) % TX_DESC_COUNT;

        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    pub fn get_tx_stats(&self) -> (u64, u64, u64) {
        (
            self.tx_packets.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
            self.tx_errors.load(Ordering::Relaxed),
        )
    }
}
