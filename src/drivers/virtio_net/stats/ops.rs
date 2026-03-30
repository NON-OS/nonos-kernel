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

use core::sync::atomic::Ordering;
use super::types::NetworkStats;
use super::snapshot::NetworkStatsSnapshot;
use super::super::error::VirtioNetError;

impl NetworkStats {
    pub fn new() -> Self { Self::default() }

    pub fn record_error(&self, error: VirtioNetError) {
        match error {
            VirtioNetError::MalformedPacket => { self.malformed_packets.fetch_add(1, Ordering::Relaxed); }
            VirtioNetError::InvalidHeader => { self.invalid_headers.fetch_add(1, Ordering::Relaxed); }
            VirtioNetError::ChecksumError => { self.checksum_errors.fetch_add(1, Ordering::Relaxed); }
            VirtioNetError::InvalidMacAddress => { self.invalid_mac_errors.fetch_add(1, Ordering::Relaxed); }
            VirtioNetError::RateLimitExceeded => { self.rate_limit_violations.fetch_add(1, Ordering::Relaxed); }
            VirtioNetError::DescriptorOutOfBounds | VirtioNetError::DescriptorChainTooLong => { self.descriptor_errors.fetch_add(1, Ordering::Relaxed); }
            VirtioNetError::InvalidDmaAddress => { self.dma_errors.fetch_add(1, Ordering::Relaxed); }
            VirtioNetError::QueueError => { self.queue_errors.fetch_add(1, Ordering::Relaxed); }
            VirtioNetError::PacketTooSmall | VirtioNetError::PacketExceedsMtu | VirtioNetError::InvalidPacketSize => { self.packet_size_errors.fetch_add(1, Ordering::Relaxed); }
            VirtioNetError::NoBuffersAvailable | VirtioNetError::BufferTooSmall | VirtioNetError::AllocationFailed => { self.buffer_errors.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }

    pub fn record_rx(&self, bytes: usize) { self.rx_packets.fetch_add(1, Ordering::Relaxed); self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed); }
    pub fn record_tx(&self, bytes: usize) { self.tx_packets.fetch_add(1, Ordering::Relaxed); self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed); }
    pub fn record_rx_error(&self) { self.rx_errors.fetch_add(1, Ordering::Relaxed); }
    pub fn record_tx_error(&self) { self.tx_errors.fetch_add(1, Ordering::Relaxed); }
    pub fn record_rx_drop(&self) { self.rx_dropped.fetch_add(1, Ordering::Relaxed); }
    pub fn record_tx_drop(&self) { self.tx_dropped.fetch_add(1, Ordering::Relaxed); }

    pub fn snapshot(&self) -> NetworkStatsSnapshot {
        NetworkStatsSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed), tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed), tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_errors: self.rx_errors.load(Ordering::Relaxed), tx_errors: self.tx_errors.load(Ordering::Relaxed),
            rx_dropped: self.rx_dropped.load(Ordering::Relaxed), tx_dropped: self.tx_dropped.load(Ordering::Relaxed),
            malformed_packets: self.malformed_packets.load(Ordering::Relaxed), invalid_headers: self.invalid_headers.load(Ordering::Relaxed),
            checksum_errors: self.checksum_errors.load(Ordering::Relaxed), invalid_mac_errors: self.invalid_mac_errors.load(Ordering::Relaxed),
            rate_limit_violations: self.rate_limit_violations.load(Ordering::Relaxed), descriptor_errors: self.descriptor_errors.load(Ordering::Relaxed),
            dma_errors: self.dma_errors.load(Ordering::Relaxed), queue_errors: self.queue_errors.load(Ordering::Relaxed),
            packet_size_errors: self.packet_size_errors.load(Ordering::Relaxed), buffer_errors: self.buffer_errors.load(Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        self.rx_packets.store(0, Ordering::Relaxed); self.tx_packets.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed); self.tx_bytes.store(0, Ordering::Relaxed);
        self.rx_errors.store(0, Ordering::Relaxed); self.tx_errors.store(0, Ordering::Relaxed);
        self.rx_dropped.store(0, Ordering::Relaxed); self.tx_dropped.store(0, Ordering::Relaxed);
        self.malformed_packets.store(0, Ordering::Relaxed); self.invalid_headers.store(0, Ordering::Relaxed);
        self.checksum_errors.store(0, Ordering::Relaxed); self.invalid_mac_errors.store(0, Ordering::Relaxed);
        self.rate_limit_violations.store(0, Ordering::Relaxed); self.descriptor_errors.store(0, Ordering::Relaxed);
        self.dma_errors.store(0, Ordering::Relaxed); self.queue_errors.store(0, Ordering::Relaxed);
        self.packet_size_errors.store(0, Ordering::Relaxed); self.buffer_errors.store(0, Ordering::Relaxed);
    }

    pub fn total_security_errors(&self) -> u64 {
        self.malformed_packets.load(Ordering::Relaxed) + self.invalid_headers.load(Ordering::Relaxed)
            + self.checksum_errors.load(Ordering::Relaxed) + self.invalid_mac_errors.load(Ordering::Relaxed)
            + self.rate_limit_violations.load(Ordering::Relaxed)
    }
}
