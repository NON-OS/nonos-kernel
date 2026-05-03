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

use super::constants::*;
use super::core::RealtekWifiDevice;
use crate::drivers::pci::{pci_read_config32, pci_write_config32};

impl Drop for RealtekWifiDevice {
    fn drop(&mut self) {
        self.write32(regs::CR, 0);
        self.write16(regs::HIMR, 0);
        self.delay_us(100);

        /* disable bus master in PCI command register */
        let cmd = pci_read_config32(
            self.pci_device.bus,
            self.pci_device.device,
            self.pci_device.function,
            0x04,
        );
        pci_write_config32(
            self.pci_device.bus,
            self.pci_device.device,
            self.pci_device.function,
            0x04,
            cmd & !0x04,
        );

        if let Err(e) = crate::memory::dma::free_coherent(self.tx_ring_virt) {
            crate::log_warn!("rtlwifi: failed to free tx ring: {:?}", e);
        }
        if let Err(e) = crate::memory::dma::free_coherent(self.rx_ring_virt) {
            crate::log_warn!("rtlwifi: failed to free rx ring: {:?}", e);
        }
        if let Err(e) = crate::memory::dma::free_coherent(self.tx_buffers_virt) {
            crate::log_warn!("rtlwifi: failed to free tx buffers: {:?}", e);
        }
        if let Err(e) = crate::memory::dma::free_coherent(self.rx_buffers_virt) {
            crate::log_warn!("rtlwifi: failed to free rx buffers: {:?}", e);
        }

        crate::log::info!("rtlwifi: device resources released");
    }
}
