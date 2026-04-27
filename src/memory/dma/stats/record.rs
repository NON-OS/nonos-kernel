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

use super::types::DmaStats;
use core::sync::atomic::Ordering;

impl DmaStats {
    pub fn record_coherent_alloc(&self, size: usize) {
        self.coherent_allocations.fetch_add(1, Ordering::Relaxed);
        self.total_dma_memory.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn record_coherent_free(&self, size: usize) {
        self.coherent_allocations.fetch_sub(1, Ordering::Relaxed);
        self.total_dma_memory.fetch_sub(size as u64, Ordering::Relaxed);
    }

    pub fn record_streaming_map(&self) {
        self.streaming_mappings.fetch_add(1, Ordering::Relaxed);
        self.dma_operations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_streaming_unmap(&self) {
        self.streaming_mappings.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_bounce_usage(&self, used: bool) {
        if used {
            self.bounce_buffer_usage.fetch_add(1, Ordering::Relaxed);
        } else {
            self.bounce_buffer_usage.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
