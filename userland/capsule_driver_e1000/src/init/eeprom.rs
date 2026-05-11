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

//! EEPROM-backed MAC read. The first three 16-bit EEPROM words
//! hold the device's MAC; each is fetched via EERD by writing the
//! address with `START` set and polling `DONE`.

use crate::constants::regs::REG_EERD;
use crate::constants::status::{EERD_ADDR_SHIFT, EERD_DATA_SHIFT, EERD_DONE, EERD_START};
use crate::constants::MAC_LEN;
use crate::regs::Regs;

const EERD_POLL_BUDGET: u32 = 100_000;

pub fn read_mac(regs: &Regs) -> Result<[u8; MAC_LEN], &'static str> {
    let mut mac = [0u8; MAC_LEN];
    for word in 0u8..3 {
        let value = read_word(regs, word)?;
        mac[(word as usize) * 2] = (value & 0xFF) as u8;
        mac[(word as usize) * 2 + 1] = ((value >> 8) & 0xFF) as u8;
    }
    Ok(mac)
}

fn read_word(regs: &Regs, word: u8) -> Result<u16, &'static str> {
    // SAFETY: eK@nonos.systems — `regs` carries a valid broker
    // MmioMap base; EERD offset is 4-byte aligned per the 8254x
    // manual.
    unsafe {
        regs.w32(REG_EERD, ((word as u32) << EERD_ADDR_SHIFT) | EERD_START);
        let mut spins = 0u32;
        loop {
            let v = regs.r32(REG_EERD);
            if v & EERD_DONE != 0 {
                return Ok((v >> EERD_DATA_SHIFT) as u16);
            }
            spins += 1;
            if spins > EERD_POLL_BUDGET {
                return Err("EERD did not signal DONE");
            }
            core::hint::spin_loop();
        }
    }
}
