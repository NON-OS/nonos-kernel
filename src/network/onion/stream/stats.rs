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


use core::sync::atomic::{AtomicU32, AtomicU64};

#[derive(Debug, Clone)]
pub struct StreamMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub cells_sent: u32,
    pub cells_received: u32,
    pub uptime_ms: u64,
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub send_window: i32,
    pub recv_window: i32,
}

#[derive(Debug, Default)]
pub struct StreamStatistics {
    pub active_streams: AtomicU32,
    pub total_streams_created: AtomicU64,
    pub total_streams_closed: AtomicU64,
    pub total_data_transferred: AtomicU64,
    pub stream_creation_rate: AtomicU32,
    pub average_stream_lifetime: AtomicU64,
}

impl StreamStatistics {
    /// Get current active stream count
    pub fn get_active_count(&self) -> u32 {
        self.active_streams.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Get total streams created
    pub fn get_total_created(&self) -> u64 {
        self.total_streams_created.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Get total streams closed
    pub fn get_total_closed(&self) -> u64 {
        self.total_streams_closed.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Get total data transferred
    pub fn get_data_transferred(&self) -> u64 {
        self.total_data_transferred.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Get stream creation rate
    pub fn get_creation_rate(&self) -> u32 {
        self.stream_creation_rate.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Get average stream lifetime
    pub fn get_average_lifetime(&self) -> u64 {
        self.average_stream_lifetime.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Record stream creation
    pub fn record_stream_created(&self) {
        self.total_streams_created.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.active_streams.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    /// Record stream closed
    pub fn record_stream_closed(&self, lifetime_ms: u64) {
        self.total_streams_closed.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.active_streams.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
        // Update average lifetime
        let total = self.total_streams_closed.load(core::sync::atomic::Ordering::Relaxed);
        if total > 0 {
            let current_avg = self.average_stream_lifetime.load(core::sync::atomic::Ordering::Relaxed);
            let new_avg = (current_avg.saturating_mul(total - 1) + lifetime_ms) / total;
            self.average_stream_lifetime.store(new_avg, core::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Record data transfer
    pub fn record_data(&self, bytes: u64) {
        self.total_data_transferred.fetch_add(bytes, core::sync::atomic::Ordering::Relaxed);
    }
}
