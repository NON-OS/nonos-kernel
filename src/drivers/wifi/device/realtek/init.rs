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

/*
Hardware initialization for Realtek WiFi devices. Sets up interrupt registers,
enables system functions, initializes DMA controllers, reads MAC address from
EEPROM/efuse, and configures RX descriptor ring buffers.
*/

use super::super::super::error::WifiError;
use super::constants::*;
use super::core::RealtekWifiDevice;
use super::descriptors::RtlRxDesc;

impl RealtekWifiDevice {
    pub(crate) fn hw_init(&mut self) -> Result<(), WifiError> {
        self.write32(regs::HIMR, bits::IMR_DISABLED);
        self.write32(regs::HISR, bits::ISR_CLEAR);
        self.write32(regs::HIMRE, bits::IMR_DISABLED);
        self.write32(regs::HISRE, bits::ISR_CLEAR);

        let sys_func = self.read16(regs::SYS_FUNC_EN);
        self.write16(
            regs::SYS_FUNC_EN,
            sys_func | bits::SYS_FUNC_EN_CPUEN | bits::SYS_FUNC_EN_PCIED,
        );

        self.delay_us(100);

        let cr = self.read32(regs::CR as u16);
        self.write32(regs::CR as u16, cr | 0xFF);

        self.delay_us(100);

        self.write8(regs::TRXDMA_CTRL as u16, bits::TXDMA_INIT_VALUE);
        self.delay_us(10);

        Ok(())
    }

    pub(crate) fn read_mac_address(&mut self) {
        for i in 0..6 {
            self.mac_address[i] = self.read8(regs::MAC_ADDR + i as u16);
        }

        if self.mac_address == [0xFF; 6] || self.mac_address == [0; 6] {
            self.mac_address = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        }
    }

    pub(crate) fn setup_rings(&mut self) {
        for i in 0..RX_RING_SIZE {
            let desc_ptr = (self.rx_ring_virt.as_u64() + (i * core::mem::size_of::<RtlRxDesc>()) as u64) as *mut RtlRxDesc;
            let buf_addr = self.rx_buffers_phys.as_u64() + (i * RX_BUFFER_SIZE) as u64;

            unsafe {
                let desc = &*desc_ptr;
                desc.configure_rx(RX_BUFFER_SIZE as u16, buf_addr);
            }
        }
    }
}
