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

//! DMA Statistics (Lock-Free)

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::types::DmaStatsSnapshot;

/// Internal lock-free DMA statistics.
pub struct DmaStats {
    /// Number of coherent allocations
    pub(crate) coherent_allocations: AtomicUsize,
    /// Number of active streaming mappings
    pub(crate) streaming_mappings: AtomicUsize,
    /// Number of bounce buffers in use
    pub(crate) bounce_buffer_usage: AtomicUsize,
    /// Total DMA memory allocated (bytes)
    pub(crate) total_dma_memory: AtomicU64,
    /// Total DMA operations performed
    pub(crate) dma_operations: AtomicU64,
}

impl DmaStats {
    /// Creates new statistics (all zeros).
    pub const fn new() -> Self {
        Self {
            coherent_allocations: AtomicUsize::new(0),
            streaming_mappings: AtomicUsize::new(0),
            bounce_buffer_usage: AtomicUsize::new(0),
            total_dma_memory: AtomicU64::new(0),
            dma_operations: AtomicU64::new(0),
        }
    }

    /// Records a coherent allocation.
    pub fn record_coherent_alloc(&self, size: usize) {
        self.coherent_allocations.fetch_add(1, Ordering::Relaxed);
        self.total_dma_memory
            .fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Records a coherent free.
    pub fn record_coherent_free(&self, size: usize) {
        self.coherent_allocations.fetch_sub(1, Ordering::Relaxed);
        self.total_dma_memory
            .fetch_sub(size as u64, Ordering::Relaxed);
    }

    /// Records a streaming mapping.
    pub fn record_streaming_map(&self) {
        self.streaming_mappings.fetch_add(1, Ordering::Relaxed);
        self.dma_operations.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a streaming unmap.
    pub fn record_streaming_unmap(&self) {
        self.streaming_mappings.fetch_sub(1, Ordering::Relaxed);
    }

    /// Records bounce buffer usage.
    pub fn record_bounce_usage(&self, used: bool) {
        if used {
            self.bounce_buffer_usage.fetch_add(1, Ordering::Relaxed);
        } else {
            self.bounce_buffer_usage.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Creates a snapshot of current statistics.
    pub fn snapshot(&self) -> DmaStatsSnapshot {
        DmaStatsSnapshot {
            coherent_allocations: self.coherent_allocations.load(Ordering::Relaxed),
            streaming_mappings: self.streaming_mappings.load(Ordering::Relaxed),
            bounce_buffer_usage: self.bounce_buffer_usage.load(Ordering::Relaxed),
            total_dma_memory: self.total_dma_memory.load(Ordering::Relaxed),
            dma_operations: self.dma_operations.load(Ordering::Relaxed),
        }
    }

    /// Returns total DMA memory.
    pub fn total_memory(&self) -> u64 {
        self.total_dma_memory.load(Ordering::Relaxed)
    }

    /// Returns coherent allocation count.
    pub fn coherent_count(&self) -> usize {
        self.coherent_allocations.load(Ordering::Relaxed)
    }

    /// Returns streaming mapping count.
    pub fn streaming_count(&self) -> usize {
        self.streaming_mappings.load(Ordering::Relaxed)
    }
}

impl Default for DmaStats {
    fn default() -> Self {
        Self::new()
    }
}
