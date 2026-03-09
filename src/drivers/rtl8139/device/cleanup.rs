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

use super::core::Rtl8139Device;
use crate::drivers::rtl8139::constants::{reg, TX_DESC_COUNT};
use crate::drivers::rtl8139::io::{outb, outw};

impl Rtl8139Device {
    pub(crate) fn shutdown_hardware(&mut self) {
        outw(self.io_base + reg::IMR, 0);
        outb(self.io_base + reg::CR, 0);

        for _ in 0..1000 {
            core::hint::spin_loop();
        }

        outw(self.io_base + reg::ISR, 0xFFFF);
    }
}

impl Drop for Rtl8139Device {
    fn drop(&mut self) {
        self.shutdown_hardware();

        /* rx buffer */
        if let Err(e) = crate::memory::dma::free_coherent(self.rx_buffer_virt) {
            crate::log_warn!("rtl8139: failed to free rx buffer: {:?}", e);
        }

        /* tx buffers */
        for i in 0..TX_DESC_COUNT {
            if self.tx_buffers_virt[i].as_u64() != 0 {
                if let Err(e) = crate::memory::dma::free_coherent(self.tx_buffers_virt[i]) {
                    crate::log_warn!("rtl8139: failed to free tx buffer {}: {:?}", i, e);
                }
            }
        }

        crate::log::info!("rtl8139: device resources released");
    }
}
