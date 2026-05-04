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

pub(super) fn handle_timer_softirq() {
    crate::interrupts::timer::tick::tick();
}

pub(super) fn handle_net_tx_softirq() {
    if let Some(dev) = crate::drivers::virtio_net::get_virtio_net_device() {
        dev.lock().reclaim_tx();
    }
    crate::drivers::network::e1000::poll();
    crate::drivers::rtl8139::poll();
    crate::drivers::rtl8168::poll();
}

pub(super) fn handle_net_rx_softirq() {
    crate::network::manager::poll_network();
}

pub(super) fn handle_block_softirq() {
    let _ = crate::fs::cache::process_inode_cache_maintenance(16);
}

pub(super) fn handle_irq_poll_softirq() {
    crate::drivers::network::e1000::poll();
    crate::drivers::rtl8139::poll();
    crate::drivers::rtl8168::poll();
}

pub(super) fn handle_sched_softirq() {
    crate::sched::scheduler::process::check_sleeping_processes();
    crate::sched::scheduler::process::wakeup();
}

pub(super) fn handle_hrtimer_softirq() {
    crate::interrupts::timer::tick::tick();
}
