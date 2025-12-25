// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! Low-level MMIO register access and utility functions.

use x86_64::VirtAddr;
use crate::memory::mmio::{mmio_r32, mmio_w32};

use super::super::constants::*;

/// Trait for AHCI register access operations.
pub trait RegisterAccess {
    /// Get the MMIO base address.
    fn base_addr(&self) -> usize;

    /// Read an HBA register.
    fn read_hba_reg(&self, offset: u32) -> u32 {
        // SAFETY: base_addr + offset is a valid MMIO address for AHCI registers
        unsafe { mmio_r32(VirtAddr::new((self.base_addr() + offset as usize) as u64)) }
    }

    /// Write an HBA register.
    fn write_hba_reg(&self, offset: u32, value: u32) {
        // SAFETY: base_addr + offset is a valid MMIO address for AHCI registers
        unsafe { mmio_w32(VirtAddr::new((self.base_addr() + offset as usize) as u64), value) }
    }

    /// Read a port register.
    fn read_port_reg(&self, port: u32, offset: u32) -> u32 {
        let port_offset = 0x100 + (port * 0x80) + offset;
        self.read_hba_reg(port_offset)
    }

    /// Write a port register.
    fn write_port_reg(&self, port: u32, offset: u32, value: u32) {
        let port_offset = 0x100 + (port * 0x80) + offset;
        self.write_hba_reg(port_offset, value)
    }

    /// Wait while condition is true, up to `iters` iterations.
    fn wait_while<F: Fn() -> bool>(&self, cond: F, mut iters: u32) -> bool {
        while iters > 0 {
            if !cond() { return true; }
            iters -= 1;
        }
        false
    }

    /// Get timestamp in microseconds (CPU cycle approximation).
    fn get_timestamp_us(&self) -> u64 {
        // SAFETY: _rdtsc reads the timestamp counter, which is always safe
        unsafe {
            let tsc = core::arch::x86_64::_rdtsc();
            // Assume ~2GHz CPU, so divide by 2000 to get microseconds
            tsc / 2000
        }
    }
}

/// Compute header flags for command.
#[inline]
pub fn hdr_flags_for(cfis_dwords: u16, is_write: bool) -> u16 {
    let mut flags = cfis_dwords & 0x1F; // CFL
    if is_write { flags |= 1 << 6; }     // W
    flags
}

/// Fill H2D Register FIS for 48-bit LBA commands.
pub fn fill_h2d_fis(cfis: &mut [u8], cmd: u8, lba: u64, count: u16, _is_write: bool) {
    for b in cfis.iter_mut() { *b = 0; }
    cfis[0] = FIS_TYPE_REG_H2D;
    cfis[1] = 1 << 7; // C = 1, PM port 0
    cfis[2] = cmd;

    // LBA[0..5]
    cfis[4] = (lba & 0xFF) as u8;
    cfis[5] = ((lba >> 8) & 0xFF) as u8;
    cfis[6] = ((lba >> 16) & 0xFF) as u8;
    cfis[7] = 0x40; // device (bit 6 = LBA mode)
    cfis[8] = ((lba >> 24) & 0xFF) as u8;
    cfis[9] = ((lba >> 32) & 0xFF) as u8;
    cfis[10] = ((lba >> 40) & 0xFF) as u8;

    // Sector count (low/high)
    cfis[12] = (count & 0xFF) as u8;
    cfis[13] = ((count >> 8) & 0xFF) as u8;

    // ICC, control
    cfis[14] = 0;
    cfis[15] = 0;

    // for IDENTIFY (0xEC) - clear LBA and count
    if cmd == ATA_CMD_IDENTIFY {
        cfis[4..=6].fill(0);
        cfis[8..=10].fill(0);
        cfis[12] = 0;
        cfis[13] = 0;
    }
}
