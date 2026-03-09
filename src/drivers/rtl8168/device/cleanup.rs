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

use super::core::Rtl8168Device;
use crate::drivers::rtl8168::constants::{reg, RX_DESC_COUNT, TX_DESC_COUNT};

impl Rtl8168Device {
    pub(crate) fn shutdown_hardware(&mut self) {
        self.write16(reg::IMR, 0);
        self.write8(reg::CR, 0);

        self.spin_delay(100);

        self.write16(reg::ISR, 0xFFFF);
    }
}

impl Drop for Rtl8168Device {
    fn drop(&mut self) {
        self.shutdown_hardware();

        /* rx descriptor ring */
        if let Err(e) = crate::memory::dma::free_coherent(self.rx_descs_virt) {
            crate::log_warn!("rtl8168: failed to free rx desc ring: {:?}", e);
        }

        /* tx descriptor ring */
        if let Err(e) = crate::memory::dma::free_coherent(self.tx_descs_virt) {
            crate::log_warn!("rtl8168: failed to free tx desc ring: {:?}", e);
        }

        /* rx packet buffers */
        for i in 0..RX_DESC_COUNT {
            if self.rx_buffers_virt[i].as_u64() != 0 {
                if let Err(e) = crate::memory::dma::free_coherent(self.rx_buffers_virt[i]) {
                    crate::log_warn!("rtl8168: failed to free rx buffer {}: {:?}", i, e);
                }
            }
        }

        /* tx packet buffers */
        for i in 0..TX_DESC_COUNT {
            if self.tx_buffers_virt[i].as_u64() != 0 {
                if let Err(e) = crate::memory::dma::free_coherent(self.tx_buffers_virt[i]) {
                    crate::log_warn!("rtl8168: failed to free tx buffer {}: {:?}", i, e);
                }
            }
        }

        crate::log::info!("rtl8168: device resources released");
    }
}
