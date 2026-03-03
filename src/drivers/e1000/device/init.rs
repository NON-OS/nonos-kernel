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

use super::super::constants::*;
use super::super::descriptors::{E1000RxDesc, E1000TxDesc};
use super::core::E1000Device;

impl E1000Device {
    pub(super) fn reset(&self) -> bool {
        self.write_reg(reg::CTRL, ctrl::RST);

        let mut reset_complete = false;
        for _ in 0..10000 {
            if self.read_reg(reg::CTRL) & ctrl::RST == 0 {
                reset_complete = true;
                break;
            }
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        if !reset_complete {
            crate::log_warn!("e1000: Reset timeout - hardware may be in unknown state");
        }

        self.write_reg(reg::IMC, 0xFFFFFFFF);
        let _icr = self.read_reg(reg::ICR);

        reset_complete
    }

    pub(super) fn read_mac_address(&mut self) {
        let ral = self.read_reg(reg::RAL0);
        let rah = self.read_reg(reg::RAH0);

        if ral != 0 || (rah & 0xFFFF) != 0 {
            self.mac_address[0] = (ral & 0xFF) as u8;
            self.mac_address[1] = ((ral >> 8) & 0xFF) as u8;
            self.mac_address[2] = ((ral >> 16) & 0xFF) as u8;
            self.mac_address[3] = ((ral >> 24) & 0xFF) as u8;
            self.mac_address[4] = (rah & 0xFF) as u8;
            self.mac_address[5] = ((rah >> 8) & 0xFF) as u8;
        } else {
            for i in 0..3 {
                let word = self.eeprom_read(i as u8).unwrap_or(0);
                self.mac_address[i * 2] = (word & 0xFF) as u8;
                self.mac_address[i * 2 + 1] = ((word >> 8) & 0xFF) as u8;
            }
            if self.mac_address == [0u8; 6] {
                crate::log_warn!("e1000: Failed to read MAC address from EEPROM, using fallback");
                self.mac_address = [0x02, 0x00, 0x00, 0xE1, 0x00, 0x00];
            }
        }

        let ral_val = (self.mac_address[0] as u32)
            | ((self.mac_address[1] as u32) << 8)
            | ((self.mac_address[2] as u32) << 16)
            | ((self.mac_address[3] as u32) << 24);
        let rah_val = (self.mac_address[4] as u32)
            | ((self.mac_address[5] as u32) << 8)
            | (1 << 31);

        self.write_reg(reg::RAL0, ral_val);
        self.write_reg(reg::RAH0, rah_val);
    }

    pub(super) fn eeprom_read(&self, addr: u8) -> Option<u16> {
        self.write_reg(reg::EERD, 1 | ((addr as u32) << 8));

        for _ in 0..10000 {
            let val = self.read_reg(reg::EERD);
            if val & (1 << 4) != 0 {
                return Some(((val >> 16) & 0xFFFF) as u16);
            }
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }

        crate::log_warn!("e1000: EEPROM read timeout at address {}", addr);
        None
    }

    pub(super) fn init_rx(&mut self) {
        let rx_descs = self.rx_descs_virt.as_mut_ptr::<E1000RxDesc>();
        for i in 0..RX_DESC_COUNT {
            // SAFETY: rx_descs points to valid descriptor ring memory
            unsafe {
                let desc = &mut *rx_descs.add(i);
                desc.buffer_addr = self.rx_buffers_phys[i].as_u64();
                desc.length = 0;
                desc.checksum = 0;
                desc.status = 0;
                desc.errors = 0;
                desc.special = 0;
            }
        }

        self.write_reg(reg::RDBAL, (self.rx_descs_phys.as_u64() & 0xFFFFFFFF) as u32);
        self.write_reg(reg::RDBAH, (self.rx_descs_phys.as_u64() >> 32) as u32);
        self.write_reg(reg::RDLEN, (RX_DESC_COUNT * 16) as u32);
        self.write_reg(reg::RDH, 0);
        self.write_reg(reg::RDT, (RX_DESC_COUNT - 1) as u32);

        self.rx_tail = RX_DESC_COUNT - 1;

        for i in 0..128 {
            self.write_reg(reg::MTA + (i * 4), 0);
        }

        let rctl_val = rctl::EN | rctl::BAM | rctl::BSIZE_2048 | rctl::SECRC;
        self.write_reg(reg::RCTL, rctl_val);
    }

    pub(super) fn init_tx(&mut self) {
        let tx_descs = self.tx_descs_virt.as_mut_ptr::<E1000TxDesc>();
        for i in 0..TX_DESC_COUNT {
            // SAFETY: tx_descs points to valid descriptor ring memory
            unsafe {
                let desc = &mut *tx_descs.add(i);
                desc.buffer_addr = self.tx_buffers_phys[i].as_u64();
                desc.length = 0;
                desc.cso = 0;
                desc.cmd = 0;
                desc.status = 1;
                desc.css = 0;
                desc.special = 0;
            }
        }

        self.write_reg(reg::TDBAL, (self.tx_descs_phys.as_u64() & 0xFFFFFFFF) as u32);
        self.write_reg(reg::TDBAH, (self.tx_descs_phys.as_u64() >> 32) as u32);
        self.write_reg(reg::TDLEN, (TX_DESC_COUNT * 16) as u32);
        self.write_reg(reg::TDH, 0);
        self.write_reg(reg::TDT, 0);

        self.tx_tail = 0;

        self.write_reg(reg::TIPG, DEFAULT_TIPG);

        let tctl_val = tctl::EN
            | tctl::PSP
            | (DEFAULT_COLLISION_THRESHOLD << tctl::CT_SHIFT)
            | (DEFAULT_COLLISION_DISTANCE << tctl::COLD_SHIFT)
            | tctl::RTLC;
        self.write_reg(reg::TCTL, tctl_val);
    }

    pub(super) fn enable_interrupts(&self) {
        self.write_reg(reg::IMS, int::TXDW | int::LSC | int::RXT0 | int::RXDMT0);
    }
}
