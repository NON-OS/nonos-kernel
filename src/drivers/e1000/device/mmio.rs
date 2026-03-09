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
use crate::drivers::e1000::constants::{ctrl, reg};

impl E1000Device {
    #[inline]
    pub(super) fn read_reg(&self, offset: u32) -> u32 {
        // SAFETY: mmio_base + offset is a valid MMIO register address
        unsafe {
            let addr = (self.mmio_base.as_u64() + offset as u64) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    #[inline]
    pub(super) fn write_reg(&self, offset: u32, value: u32) {
        // SAFETY: mmio_base + offset is a valid MMIO register address
        unsafe {
            let addr = (self.mmio_base.as_u64() + offset as u64) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

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
}
