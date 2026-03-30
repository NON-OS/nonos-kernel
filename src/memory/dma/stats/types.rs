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

use core::sync::atomic::{AtomicU64, AtomicUsize};

pub struct DmaStats {
    pub(crate) coherent_allocations: AtomicUsize,
    pub(crate) streaming_mappings: AtomicUsize,
    pub(crate) bounce_buffer_usage: AtomicUsize,
    pub(crate) total_dma_memory: AtomicU64,
    pub(crate) dma_operations: AtomicU64,
}

impl DmaStats {
    pub const fn new() -> Self {
        Self {
            coherent_allocations: AtomicUsize::new(0),
            streaming_mappings: AtomicUsize::new(0),
            bounce_buffer_usage: AtomicUsize::new(0),
            total_dma_memory: AtomicU64::new(0),
            dma_operations: AtomicU64::new(0),
        }
    }
}

impl Default for DmaStats {
    fn default() -> Self {
        Self::new()
    }
}
