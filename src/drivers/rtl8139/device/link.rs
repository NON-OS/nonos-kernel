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
use crate::drivers::rtl8139::constants::{cmd, int, msr, reg};
use crate::drivers::rtl8139::io::{inb, inw, outb, outw};

impl Rtl8139Device {
    pub(crate) fn enable_transceiver(&self) {
        outb(self.io_base + reg::CR, cmd::TE | cmd::RE);
    }

    pub(crate) fn enable_interrupts(&self) {
        outw(
            self.io_base + reg::IMR,
            int::ROK | int::TOK | int::RER | int::TER | int::RXOVW | int::FOVW | int::PUN,
        );
    }

    pub fn update_link_status(&mut self) {
        let msr_val = inb(self.io_base + reg::MSR);
        self.link_up = (msr_val & msr::LINKB) == 0;
        self.link_speed = if msr_val & msr::SPEED10 != 0 {
            10
        } else {
            100
        };
    }

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
}
