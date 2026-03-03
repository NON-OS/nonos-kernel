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


use x86_64::VirtAddr;
use crate::memory::mmio::{mmio_r32, mmio_w32};

use super::super::constants::*;

pub trait RegisterAccess {
    fn base_addr(&self) -> usize;

    fn read_hba_reg(&self, offset: u32) -> u32 {
        // SAFETY: base_addr + offset is a valid MMIO address for AHCI registers.
        mmio_r32(VirtAddr::new((self.base_addr() + offset as usize) as u64))
    }

    fn write_hba_reg(&self, offset: u32, value: u32) {
        // SAFETY: base_addr + offset is a valid MMIO address for AHCI registers.
        mmio_w32(VirtAddr::new((self.base_addr() + offset as usize) as u64), value)
    }

    fn read_port_reg(&self, port: u32, offset: u32) -> u32 {
        let port_offset = 0x100 + (port * 0x80) + offset;
        self.read_hba_reg(port_offset)
    }

    fn write_port_reg(&self, port: u32, offset: u32, value: u32) {
        let port_offset = 0x100 + (port * 0x80) + offset;
        self.write_hba_reg(port_offset, value)
    }

    fn wait_while<F: Fn() -> bool>(&self, cond: F, mut iters: u32) -> bool {
        while iters > 0 {
            if !cond() { return true; }
            iters -= 1;
        }
        false
    }

    fn get_timestamp_us(&self) -> u64 {
        crate::arch::x86_64::time::tsc::elapsed_us()
    }
}

#[inline]
pub fn hdr_flags_for(cfis_dwords: u16, is_write: bool) -> u16 {
    let mut flags = cfis_dwords & 0x1F;
    if is_write { flags |= 1 << 6; }
    flags
}

pub(super) fn fill_h2d_fis(cfis: &mut [u8], cmd: u8, lba: u64, count: u16, _is_write: bool) {
    for b in cfis.iter_mut() { *b = 0; }
    cfis[0] = FIS_TYPE_REG_H2D;
    cfis[1] = 1 << 7;
    cfis[2] = cmd;

    cfis[4] = (lba & 0xFF) as u8;
    cfis[5] = ((lba >> 8) & 0xFF) as u8;
    cfis[6] = ((lba >> 16) & 0xFF) as u8;
    cfis[7] = 0x40;
    cfis[8] = ((lba >> 24) & 0xFF) as u8;
    cfis[9] = ((lba >> 32) & 0xFF) as u8;
    cfis[10] = ((lba >> 40) & 0xFF) as u8;

    cfis[12] = (count & 0xFF) as u8;
    cfis[13] = ((count >> 8) & 0xFF) as u8;

    cfis[14] = 0;
    cfis[15] = 0;

    if cmd == ATA_CMD_IDENTIFY {
        cfis[4..=6].fill(0);
        cfis[8..=10].fill(0);
        cfis[12] = 0;
        cfis[13] = 0;
    }
}
