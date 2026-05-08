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

//! Clear the interrupter's IP latch and the broker's IRQ grant
//! ack. The controller's IMAN.IP is write-1-to-clear; once cleared,
//! the line can fire again on the next event. The broker-side
//! `mk_irq_ack` releases the kernel-side queue slot so the next
//! `mk_irq_poll` can block.

use nonos_libc::mk_irq_ack;

use crate::constants::IMAN_IP;
use crate::regs::runtime::{iman_read, iman_write};

pub fn ack_irq(intr_base: u64, irq_grant_id: u64) {
    let cur = iman_read(intr_base);
    if cur & IMAN_IP != 0 {
        iman_write(intr_base, cur | IMAN_IP);
    }
    let _ = mk_irq_ack(irq_grant_id);
}
