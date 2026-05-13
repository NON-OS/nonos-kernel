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

use crate::constants::dma::{TX_SLOT_BYTES, TX_SLOT_COUNT};
use crate::constants::regs::{REG_TCR, REG_TXADDR0, TCR_MXDMA_UNLIMITED};
use crate::setup::Driver;

pub fn program(driver: &mut Driver) -> Result<(), &'static str> {
    for idx in 0..TX_SLOT_COUNT {
        let addr = driver.tx_device_addr + (idx * TX_SLOT_BYTES) as u64;
        driver.pio.w32(REG_TXADDR0 + (idx as u16 * 4), addr as u32)?;
    }
    driver.tx_cur = 0;
    driver.pio.w32(REG_TCR, TCR_MXDMA_UNLIMITED)
}
