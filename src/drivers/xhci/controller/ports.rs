// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use x86_64::VirtAddr;
use crate::memory::mmio::{mmio_r32, mmio_w32};
use super::super::constants::*;
use super::super::error::XhciResult;
use super::XhciController;

impl XhciController {
    pub fn read_portsc(&self, port: u8) -> XhciResult<u32> {
        self.validate_port_number(port)?;
        let reg = self.op_base + OP_PORTSC_BASE + ((port as usize) - 1) * OP_PORT_REG_STRIDE;
        // SAFETY: reg points to valid port status register
        Ok(unsafe { mmio_r32(VirtAddr::new(reg as u64)) })
    }

    pub fn write_portsc(&self, port: u8, val: u32) -> XhciResult<()> {
        self.validate_port_number(port)?;
        let reg = self.op_base + OP_PORTSC_BASE + ((port as usize) - 1) * OP_PORT_REG_STRIDE;
        // SAFETY: reg points to valid port status register
        unsafe { mmio_w32(VirtAddr::new(reg as u64), val); }
        Ok(())
    }
}
