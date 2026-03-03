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


use core::sync::atomic::{AtomicU64, Ordering};
use crate::network::stack::get_network_stack;
use crate::network::onion;

static NET_POLL_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn run_network_stack() {
    loop {
        poll_network();
        onion::process_circuit_maintenance();
        crate::sched::yield_cpu();
    }
}

pub fn poll_network() {
    if let Some(dev) = crate::drivers::virtio_net::get_virtio_net_device() {
        let packets = dev.lock().receive_packets();
        for pkt in packets {
            let _ = crate::drivers::network::stack::receive_packet(&pkt);
        }
        dev.lock().reclaim_tx();
    }

    if let Some(stack) = get_network_stack() {
        stack.poll_interface();
    }
}

pub fn network_tick() {
    let count = NET_POLL_COUNTER.fetch_add(1, Ordering::Relaxed);
    if count % 10 == 0 {
        poll_network();
    }
}

pub fn get_poll_count() -> u64 {
    NET_POLL_COUNTER.load(Ordering::Relaxed)
}
