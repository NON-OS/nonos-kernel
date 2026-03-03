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

use super::super::constants::*;
use super::super::io::{inw, outw};
use super::core::Rtl8139Device;

impl Rtl8139Device {
    pub fn handle_interrupt(&mut self) {
        let isr = inw(self.io_base + reg::ISR);

        outw(self.io_base + reg::ISR, isr);

        if isr & int::RER != 0 {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
        }
        if isr & int::TER != 0 {
            self.tx_errors.fetch_add(1, Ordering::Relaxed);
        }
        if isr & int::RXOVW != 0 {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
            crate::log_warn!("rtl8139: RX buffer overflow");
        }
        if isr & int::FOVW != 0 {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
            crate::log_warn!("rtl8139: RX FIFO overflow");
        }
        if isr & int::PUN != 0 {
            self.update_link_status();
        }
    }

    pub fn get_rx_stats(&self) -> (u64, u64, u64) {
        (
            self.rx_packets.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.rx_errors.load(Ordering::Relaxed),
        )
    }

    pub fn get_tx_stats(&self) -> (u64, u64, u64) {
        (
            self.tx_packets.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
            self.tx_errors.load(Ordering::Relaxed),
        )
    }
}
