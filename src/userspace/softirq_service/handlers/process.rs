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

use super::pending;
use super::stats::{process_rcu_callbacks, process_tasklets, STATS};
use super::types::PENDING;
use core::sync::atomic::Ordering;

pub(crate) fn process_softirqs() -> usize {
    let mut processed = 0;
    let mut bitmap = PENDING.swap(0, Ordering::AcqRel);

    while bitmap != 0 {
        let irq_bit = bitmap.trailing_zeros() as u8;
        bitmap &= !(1 << irq_bit);
        process_single_softirq(irq_bit);
        processed += 1;
        if (irq_bit as usize) < 9 {
            STATS.lock().count[irq_bit as usize] += 1;
        }
    }
    processed
}

fn process_single_softirq(irq: u8) {
    match irq {
        0 => pending::handle_timer_softirq(),
        1 => pending::handle_net_tx_softirq(),
        2 => pending::handle_net_rx_softirq(),
        3 => pending::handle_block_softirq(),
        4 => pending::handle_irq_poll_softirq(),
        5 => process_tasklets(),
        6 => pending::handle_sched_softirq(),
        7 => pending::handle_hrtimer_softirq(),
        8 => process_rcu_callbacks(),
        _ => {}
    }
}
