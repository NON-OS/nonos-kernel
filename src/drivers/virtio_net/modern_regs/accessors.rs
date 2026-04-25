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

use super::common_cfg::VirtioPciCommonCfg;
use super::structure::VirtioModernRegs;
use core::ptr;

impl VirtioModernRegs {
    pub fn read_device_features(&self) -> u64 {
        unsafe { VirtioPciCommonCfg::read_device_features(self.common.as_ptr()) }
    }

    pub fn write_driver_features(&self, features: u64) {
        unsafe { VirtioPciCommonCfg::write_driver_features(self.common.as_ptr(), features) }
    }

    pub fn read_status(&self) -> u8 {
        unsafe { VirtioPciCommonCfg::read_status(self.common.as_ptr()) }
    }

    pub fn write_status(&self, status: u8) {
        unsafe { VirtioPciCommonCfg::write_status(self.common.as_ptr(), status) }
    }

    pub fn set_status_bit(&self, bit: u8) {
        let current = self.read_status();
        self.write_status(current | bit);
    }

    pub fn read_isr(&self) -> u8 {
        unsafe { ptr::read_volatile(self.isr_ptr.as_ptr()) }
    }

    pub fn read_device_cfg_byte(&self, offset: usize) -> u8 {
        if self.device_cfg == 0 {
            return 0;
        }
        unsafe { ptr::read_volatile((self.device_cfg + offset) as *const u8) }
    }

    pub fn read_device_cfg_u16(&self, offset: usize) -> u16 {
        if self.device_cfg == 0 {
            return 0;
        }
        unsafe { ptr::read_volatile((self.device_cfg + offset) as *const u16) }
    }

    pub fn read_mac_address(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = self.read_device_cfg_byte(i);
        }
        mac
    }

    pub fn queue_notify_addr(&self, notify_off: u16) -> usize {
        self.notify_base + (notify_off as usize) * (self.notify_off_multiplier as usize)
    }
}
