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

use crate::constants::queue::TX_DESC_COUNT;
use crate::constants::regs::{
    DESC_EOR, REG_TXDESC_ADDR_HI, REG_TXDESC_ADDR_LO, REG_TX_CONFIG, TX_CONFIG_DMA, TX_CONFIG_IFG,
};
use crate::queue::desc::{desc_mut, Descriptor};
use crate::queue::TxRing;
use crate::regs::Regs;

pub fn program(regs: &Regs, tx: &TxRing) {
    for i in 0..TX_DESC_COUNT {
        let eor = if i == TX_DESC_COUNT - 1 { DESC_EOR } else { 0 };
        let addr = tx.buffer_da(i);
        let d =
            Descriptor { opts1: eor, opts2: 0, addr_lo: addr as u32, addr_hi: (addr >> 32) as u32 };
        unsafe {
            desc_mut(tx.desc_va, i, d);
        }
    }
    unsafe {
        regs.w32(REG_TXDESC_ADDR_LO, tx.desc_da as u32);
        regs.w32(REG_TXDESC_ADDR_HI, (tx.desc_da >> 32) as u32);
        regs.w32(REG_TX_CONFIG, TX_CONFIG_IFG | TX_CONFIG_DMA);
    }
}
