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

use core::sync::atomic::AtomicU64;

#[derive(Default)]
pub struct NetworkStats {
    pub rx_packets: AtomicU64, pub tx_packets: AtomicU64, pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64, pub rx_errors: AtomicU64, pub tx_errors: AtomicU64,
    pub rx_dropped: AtomicU64, pub tx_dropped: AtomicU64, pub malformed_packets: AtomicU64,
    pub invalid_headers: AtomicU64, pub checksum_errors: AtomicU64, pub invalid_mac_errors: AtomicU64,
    pub rate_limit_violations: AtomicU64, pub descriptor_errors: AtomicU64, pub dma_errors: AtomicU64,
    pub queue_errors: AtomicU64, pub packet_size_errors: AtomicU64, pub buffer_errors: AtomicU64,
}
