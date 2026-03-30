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
use super::types::NetworkStats;

#[derive(Debug, Default)]
pub struct CompactNetworkStats {
    pub rx_packets: AtomicU64, pub tx_packets: AtomicU64, pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64, pub active_sockets: AtomicU64, pub packets_dropped: AtomicU64,
    pub arp_lookups: AtomicU64,
}

impl CompactNetworkStats {
    pub fn new() -> Self { Self::default() }

    pub fn from_stats(stats: &NetworkStats) -> Self {
        Self {
            rx_packets: AtomicU64::new(stats.rx_packets.load(Ordering::Relaxed)),
            tx_packets: AtomicU64::new(stats.tx_packets.load(Ordering::Relaxed)),
            rx_bytes: AtomicU64::new(stats.rx_bytes.load(Ordering::Relaxed)),
            tx_bytes: AtomicU64::new(stats.tx_bytes.load(Ordering::Relaxed)),
            active_sockets: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(stats.rx_dropped.load(Ordering::Relaxed) + stats.tx_dropped.load(Ordering::Relaxed)),
            arp_lookups: AtomicU64::new(0),
        }
    }
}
