// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use super::error::VirtioNetError;
#[derive(Default)]
pub struct NetworkStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
    pub rx_dropped: AtomicU64,
    pub tx_dropped: AtomicU64,
    pub malformed_packets: AtomicU64,
    pub invalid_headers: AtomicU64,
    pub checksum_errors: AtomicU64,
    pub invalid_mac_errors: AtomicU64,
    pub rate_limit_violations: AtomicU64,
    pub descriptor_errors: AtomicU64,
    pub dma_errors: AtomicU64,
    pub queue_errors: AtomicU64,
    pub packet_size_errors: AtomicU64,
    pub buffer_errors: AtomicU64,
}

impl NetworkStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_error(&self, error: VirtioNetError) {
        match error {
            VirtioNetError::MalformedPacket => {
                self.malformed_packets.fetch_add(1, Ordering::Relaxed);
            }
            VirtioNetError::InvalidHeader => {
                self.invalid_headers.fetch_add(1, Ordering::Relaxed);
            }
            VirtioNetError::ChecksumError => {
                self.checksum_errors.fetch_add(1, Ordering::Relaxed);
            }
            VirtioNetError::InvalidMacAddress => {
                self.invalid_mac_errors.fetch_add(1, Ordering::Relaxed);
            }
            VirtioNetError::RateLimitExceeded => {
                self.rate_limit_violations.fetch_add(1, Ordering::Relaxed);
            }
            VirtioNetError::DescriptorOutOfBounds | VirtioNetError::DescriptorChainTooLong => {
                self.descriptor_errors.fetch_add(1, Ordering::Relaxed);
            }
            VirtioNetError::InvalidDmaAddress => {
                self.dma_errors.fetch_add(1, Ordering::Relaxed);
            }
            VirtioNetError::QueueError => {
                self.queue_errors.fetch_add(1, Ordering::Relaxed);
            }
            VirtioNetError::PacketTooSmall
            | VirtioNetError::PacketExceedsMtu
            | VirtioNetError::InvalidPacketSize => {
                self.packet_size_errors.fetch_add(1, Ordering::Relaxed);
            }
            VirtioNetError::NoBuffersAvailable
            | VirtioNetError::BufferTooSmall
            | VirtioNetError::AllocationFailed => {
                self.buffer_errors.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn record_rx(&self, bytes: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_tx(&self, bytes: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_rx_error(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx_error(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rx_drop(&self) {
        self.rx_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx_drop(&self) {
        self.tx_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> NetworkStatsSnapshot {
        NetworkStatsSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_errors: self.rx_errors.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
            rx_dropped: self.rx_dropped.load(Ordering::Relaxed),
            tx_dropped: self.tx_dropped.load(Ordering::Relaxed),
            malformed_packets: self.malformed_packets.load(Ordering::Relaxed),
            invalid_headers: self.invalid_headers.load(Ordering::Relaxed),
            checksum_errors: self.checksum_errors.load(Ordering::Relaxed),
            invalid_mac_errors: self.invalid_mac_errors.load(Ordering::Relaxed),
            rate_limit_violations: self.rate_limit_violations.load(Ordering::Relaxed),
            descriptor_errors: self.descriptor_errors.load(Ordering::Relaxed),
            dma_errors: self.dma_errors.load(Ordering::Relaxed),
            queue_errors: self.queue_errors.load(Ordering::Relaxed),
            packet_size_errors: self.packet_size_errors.load(Ordering::Relaxed),
            buffer_errors: self.buffer_errors.load(Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        self.rx_packets.store(0, Ordering::Relaxed);
        self.tx_packets.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.rx_errors.store(0, Ordering::Relaxed);
        self.tx_errors.store(0, Ordering::Relaxed);
        self.rx_dropped.store(0, Ordering::Relaxed);
        self.tx_dropped.store(0, Ordering::Relaxed);
        self.malformed_packets.store(0, Ordering::Relaxed);
        self.invalid_headers.store(0, Ordering::Relaxed);
        self.checksum_errors.store(0, Ordering::Relaxed);
        self.invalid_mac_errors.store(0, Ordering::Relaxed);
        self.rate_limit_violations.store(0, Ordering::Relaxed);
        self.descriptor_errors.store(0, Ordering::Relaxed);
        self.dma_errors.store(0, Ordering::Relaxed);
        self.queue_errors.store(0, Ordering::Relaxed);
        self.packet_size_errors.store(0, Ordering::Relaxed);
        self.buffer_errors.store(0, Ordering::Relaxed);
    }

    pub fn total_security_errors(&self) -> u64 {
        self.malformed_packets.load(Ordering::Relaxed)
            + self.invalid_headers.load(Ordering::Relaxed)
            + self.checksum_errors.load(Ordering::Relaxed)
            + self.invalid_mac_errors.load(Ordering::Relaxed)
            + self.rate_limit_violations.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetworkStatsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub malformed_packets: u64,
    pub invalid_headers: u64,
    pub checksum_errors: u64,
    pub invalid_mac_errors: u64,
    pub rate_limit_violations: u64,
    pub descriptor_errors: u64,
    pub dma_errors: u64,
    pub queue_errors: u64,
    pub packet_size_errors: u64,
    pub buffer_errors: u64,
}

impl NetworkStatsSnapshot {
    pub fn total_packets(&self) -> u64 {
        self.rx_packets + self.tx_packets
    }

    pub fn total_bytes(&self) -> u64 {
        self.rx_bytes + self.tx_bytes
    }

    pub fn total_errors(&self) -> u64 {
        self.rx_errors + self.tx_errors
    }

    pub fn total_dropped(&self) -> u64 {
        self.rx_dropped + self.tx_dropped
    }

    pub fn total_security_errors(&self) -> u64 {
        self.malformed_packets
            + self.invalid_headers
            + self.checksum_errors
            + self.invalid_mac_errors
            + self.rate_limit_violations
    }

    pub fn rx_error_rate(&self) -> f64 {
        let total = self.rx_packets + self.rx_errors;
        if total == 0 {
            0.0
        } else {
            (self.rx_errors as f64 / total as f64) * 100.0
        }
    }

    pub fn tx_error_rate(&self) -> f64 {
        let total = self.tx_packets + self.tx_errors;
        if total == 0 {
            0.0
        } else {
            (self.tx_errors as f64 / total as f64) * 100.0
        }
    }

    pub fn log_report(&self) {
        crate::log::info!("=== VirtIO Network Statistics ===");
        crate::log::info!("RX: {} packets, {} bytes", self.rx_packets, self.rx_bytes);
        crate::log::info!("TX: {} packets, {} bytes", self.tx_packets, self.tx_bytes);
        crate::log::info!("Errors: RX={}, TX={}", self.rx_errors, self.tx_errors);
        crate::log::info!("Dropped: RX={}, TX={}", self.rx_dropped, self.tx_dropped);
        crate::log::info!("=== Security Statistics ===");
        crate::log::info!("Malformed packets: {}", self.malformed_packets);
        crate::log::info!("Invalid headers: {}", self.invalid_headers);
        crate::log::info!("Checksum errors: {}", self.checksum_errors);
        crate::log::info!("Invalid MAC errors: {}", self.invalid_mac_errors);
        crate::log::info!("Rate limit violations: {}", self.rate_limit_violations);
        crate::log::info!("Descriptor errors: {}", self.descriptor_errors);
        crate::log::info!("DMA errors: {}", self.dma_errors);
        crate::log::info!("Queue errors: {}", self.queue_errors);
        crate::log::info!("Packet size errors: {}", self.packet_size_errors);
        crate::log::info!("Buffer errors: {}", self.buffer_errors);
    }
}

#[derive(Debug, Default)]
pub struct CompactNetworkStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub active_sockets: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub arp_lookups: AtomicU64,
}

impl CompactNetworkStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_stats(stats: &NetworkStats) -> Self {
        Self {
            rx_packets: AtomicU64::new(stats.rx_packets.load(Ordering::Relaxed)),
            tx_packets: AtomicU64::new(stats.tx_packets.load(Ordering::Relaxed)),
            rx_bytes: AtomicU64::new(stats.rx_bytes.load(Ordering::Relaxed)),
            tx_bytes: AtomicU64::new(stats.tx_bytes.load(Ordering::Relaxed)),
            active_sockets: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(
                stats.rx_dropped.load(Ordering::Relaxed)
                    + stats.tx_dropped.load(Ordering::Relaxed),
            ),
            arp_lookups: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_creation() {
        let stats = NetworkStats::new();
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(stats.tx_packets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_rx_tx() {
        let stats = NetworkStats::new();

        stats.record_rx(100);
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(stats.rx_bytes.load(Ordering::Relaxed), 100);

        stats.record_tx(200);
        assert_eq!(stats.tx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(stats.tx_bytes.load(Ordering::Relaxed), 200);
    }

    #[test]
    fn test_error_recording() {
        let stats = NetworkStats::new();

        stats.record_error(VirtioNetError::MalformedPacket);
        assert_eq!(stats.malformed_packets.load(Ordering::Relaxed), 1);

        stats.record_error(VirtioNetError::RateLimitExceeded);
        assert_eq!(stats.rate_limit_violations.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_snapshot() {
        let stats = NetworkStats::new();
        stats.record_rx(100);
        stats.record_tx(200);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rx_packets, 1);
        assert_eq!(snapshot.tx_packets, 1);
        assert_eq!(snapshot.total_packets(), 2);
        assert_eq!(snapshot.total_bytes(), 300);
    }

    #[test]
    fn test_reset() {
        let stats = NetworkStats::new();
        stats.record_rx(100);
        stats.record_error(VirtioNetError::QueueError);

        stats.reset();

        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(stats.queue_errors.load(Ordering::Relaxed), 0);
    }
}
