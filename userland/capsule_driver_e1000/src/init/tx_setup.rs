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

//! TX bring-up. Zeros the descriptor ring, programs TDBA/TDLEN/
//! TDH/TDT, configures TIPG to the IEEE 802.3 full-duplex default
//! (`0x00602008`), and enables the transmitter via TCTL with the
//! pad-short-packet bit and a 16-retry collision threshold.

use crate::constants::queue::{TX_DESC_COUNT, TX_RING_BYTES};
use crate::constants::regs::{REG_TCTL, REG_TDBAH, REG_TDBAL, REG_TDH, REG_TDLEN, REG_TDT,
    REG_TIPG};
use crate::constants::status::{TCTL_COLD_FULL_DUPLEX, TCTL_CT_DEFAULT, TCTL_EN, TCTL_PSP};
use crate::queue::layout::TxDesc;
use crate::queue::TxRing;
use crate::regs::Regs;

const TIPG_FULL_DUPLEX: u32 = 0x0060_2008;

pub fn program(regs: &Regs, tx: &TxRing, ring_phys: u64) {
    // SAFETY: eK@nonos.systems — `tx.ring_user_va` is the broker
    // DMA grant for the descriptor ring; `TX_DESC_COUNT * 16`
    // bytes are present.
    unsafe {
        let descs = tx.ring_user_va as *mut TxDesc;
        for i in 0..TX_DESC_COUNT {
            *descs.add(i) = TxDesc::default();
        }
        regs.w32(REG_TDBAL, (ring_phys & 0xFFFF_FFFF) as u32);
        regs.w32(REG_TDBAH, (ring_phys >> 32) as u32);
        regs.w32(REG_TDLEN, TX_RING_BYTES as u32);
        regs.w32(REG_TDH, 0);
        regs.w32(REG_TDT, 0);
        regs.w32(REG_TIPG, TIPG_FULL_DUPLEX);
        regs.w32(REG_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT_DEFAULT | TCTL_COLD_FULL_DUPLEX);
    }
}
