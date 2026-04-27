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
        crate::log::info!(
            "Malformed: {}, Invalid headers: {}, Checksum: {}",
            self.malformed_packets,
            self.invalid_headers,
            self.checksum_errors
        );
        crate::log::info!(
            "Invalid MAC: {}, Rate limit: {}",
            self.invalid_mac_errors,
            self.rate_limit_violations
        );
        crate::log::info!(
            "Descriptor: {}, DMA: {}, Queue: {}",
            self.descriptor_errors,
            self.dma_errors,
            self.queue_errors
        );
        crate::log::info!(
            "Packet size: {}, Buffer: {}",
            self.packet_size_errors,
            self.buffer_errors
        );
    }
}
