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

use crate::constants::dma::RX_BUF_DATA_BYTES;
use crate::constants::regs::{
    RCR_ACCEPT_BCAST, RCR_ACCEPT_MULTI, RCR_ACCEPT_PHYS, RCR_MXDMA_UNLIMITED, RCR_WRAP, REG_CAPR,
    REG_RBSTART, REG_RCR,
};
use crate::setup::Driver;

pub fn program(driver: &mut Driver) -> Result<(), &'static str> {
    driver.rx_offset = 0;
    driver.pio.w32(REG_RBSTART, driver.rx_device_addr as u32)?;
    driver.pio.w16(REG_CAPR, capr_for(0))?;
    driver.pio.w32(
        REG_RCR,
        RCR_ACCEPT_PHYS | RCR_ACCEPT_MULTI | RCR_ACCEPT_BCAST | RCR_WRAP | RCR_MXDMA_UNLIMITED,
    )
}

fn capr_for(offset: usize) -> u16 {
    ((offset + RX_BUF_DATA_BYTES - 16) % RX_BUF_DATA_BYTES) as u16
}
