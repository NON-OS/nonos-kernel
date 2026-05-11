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

//! RX bring-up. Zeros the descriptor ring, primes every slot with
//! its phys-addr from the buffer pool, programs RDBA/RDLEN/RDH/RDT
//! and finally enables the receiver via RCTL. RDT points at the
//! last valid descriptor index per the 8254x manual.

use crate::constants::queue::{RX_DESC_COUNT, RX_RING_BYTES};
use crate::constants::regs::{REG_RCTL, REG_RDBAH, REG_RDBAL, REG_RDH, REG_RDLEN, REG_RDT};
use crate::constants::status::{RCTL_BAM, RCTL_BSIZE_2048, RCTL_EN, RCTL_SECRC};
use crate::queue::layout::RxDesc;
use crate::queue::RxRing;
use crate::regs::Regs;

pub fn program(regs: &Regs, rx: &RxRing, ring_phys: u64) {
    // SAFETY: eK@nonos.systems — `rx.ring_user_va` is the broker
    // DMA grant for the descriptor ring; `RX_DESC_COUNT * 16`
    // bytes are present.
    unsafe {
        let descs = rx.ring_user_va as *mut RxDesc;
        for i in 0..RX_DESC_COUNT {
            let d = &mut *descs.add(i);
            *d = RxDesc::default();
            d.buffer_addr = rx.buffer_phys(i as u16);
        }
        regs.w32(REG_RDBAL, (ring_phys & 0xFFFF_FFFF) as u32);
        regs.w32(REG_RDBAH, (ring_phys >> 32) as u32);
        regs.w32(REG_RDLEN, RX_RING_BYTES as u32);
        regs.w32(REG_RDH, 0);
        regs.w32(REG_RDT, (RX_DESC_COUNT as u32) - 1);
        regs.w32(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC);
    }
}
