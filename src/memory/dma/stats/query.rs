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

use super::super::types::DmaStatsSnapshot;
use super::types::DmaStats;
use core::sync::atomic::Ordering;

impl DmaStats {
    pub fn snapshot(&self) -> DmaStatsSnapshot {
        DmaStatsSnapshot {
            coherent_allocations: self.coherent_allocations.load(Ordering::Relaxed),
            streaming_mappings: self.streaming_mappings.load(Ordering::Relaxed),
            bounce_buffer_usage: self.bounce_buffer_usage.load(Ordering::Relaxed),
            total_dma_memory: self.total_dma_memory.load(Ordering::Relaxed),
            dma_operations: self.dma_operations.load(Ordering::Relaxed),
        }
    }

    pub fn total_memory(&self) -> u64 {
        self.total_dma_memory.load(Ordering::Relaxed)
    }

    pub fn coherent_count(&self) -> usize {
        self.coherent_allocations.load(Ordering::Relaxed)
    }

    pub fn streaming_count(&self) -> usize {
        self.streaming_mappings.load(Ordering::Relaxed)
    }
}
