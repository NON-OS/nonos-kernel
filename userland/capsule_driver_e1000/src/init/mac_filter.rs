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

//! Program the device's primary receive-address pair (RAL0/RAH0)
//! with the EEPROM MAC and clear the multicast table array. The
//! MTA must be zeroed in software because the device leaves the
//! 128 entries undefined out of reset; without this clear the NIC
//! would accept random multicast traffic.

use crate::constants::regs::{MTA_ENTRY_COUNT, REG_MTA_BASE, REG_RAH0, REG_RAL0};
use crate::constants::status::RAH_AV;
use crate::constants::MAC_LEN;
use crate::regs::Regs;

pub fn program(regs: &Regs, mac: &[u8; MAC_LEN]) {
    let low = (mac[0] as u32)
        | ((mac[1] as u32) << 8)
        | ((mac[2] as u32) << 16)
        | ((mac[3] as u32) << 24);
    let high = (mac[4] as u32) | ((mac[5] as u32) << 8) | RAH_AV;
    // SAFETY: eK@nonos.systems — `regs` carries a valid broker
    // MmioMap base; offsets are within BAR0.
    unsafe {
        regs.w32(REG_RAL0, low);
        regs.w32(REG_RAH0, high);
        for i in 0..MTA_ENTRY_COUNT {
            regs.w32(REG_MTA_BASE + i * 4, 0);
        }
    }
}
