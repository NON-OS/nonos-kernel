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

use crate::constants::regs::REG_MAC0;
use crate::constants::MAC_LEN;
use crate::pio::Pio;

pub fn read(pio: &Pio) -> Result<[u8; MAC_LEN], &'static str> {
    let mut mac = [0u8; MAC_LEN];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = pio.r8(REG_MAC0 + i as u16)?;
    }
    if mac == [0; MAC_LEN] || mac == [0xFF; MAC_LEN] {
        Err("rtl8139 invalid mac")
    } else {
        Ok(mac)
    }
}
