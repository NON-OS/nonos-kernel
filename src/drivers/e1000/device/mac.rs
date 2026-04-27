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

use super::core::E1000Device;
use crate::drivers::e1000::constants::reg;

impl E1000Device {
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
        let rah_val =
            (self.mac_address[4] as u32) | ((self.mac_address[5] as u32) << 8) | (1 << 31);

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
}
