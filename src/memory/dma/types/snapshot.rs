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
pub struct DmaStatsSnapshot {
    pub coherent_allocations: usize,
    pub streaming_mappings: usize,
    pub bounce_buffer_usage: usize,
    pub total_dma_memory: u64,
    pub dma_operations: u64,
}

impl DmaStatsSnapshot {
    pub const fn new() -> Self {
        Self {
            coherent_allocations: 0,
            streaming_mappings: 0,
            bounce_buffer_usage: 0,
            total_dma_memory: 0,
            dma_operations: 0,
        }
    }
}
