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
