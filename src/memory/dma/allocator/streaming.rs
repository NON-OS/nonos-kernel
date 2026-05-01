// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::error::{DmaError, DmaResult};
use super::super::stats::DmaStats;
use super::super::types::{DmaConstraints, DmaDirection, StreamingMapping};
use super::core::DmaAllocator;
use core::sync::atomic::{compiler_fence, Ordering};
use crate::memory::addr::VirtAddr;

impl DmaAllocator {
    pub fn map_streaming(
        &mut self,
        buffer_va: VirtAddr,
        size: usize,
        direction: DmaDirection,
        constraints: DmaConstraints,
        stats: &DmaStats,
    ) -> DmaResult<u64> {
        let mapping_id = self.next_mapping_id;
        self.next_mapping_id += 1;
        let needs_bounce = self.needs_bounce_buffer(buffer_va, size, &constraints)?;
        let (dma_addr, bounce_buffer) = if needs_bounce {
            let bounce_region = self.allocate_coherent(size, constraints, stats)?;
            if direction.writes_to_device() {
                self.copy_buffer(buffer_va, bounce_region.virt_addr, size)?;
            }
            stats.record_bounce_usage(true);
            (bounce_region.phys_addr, Some(bounce_region))
        } else {
            (self.translate_to_physical(buffer_va)?, None)
        };
        let mapping =
            StreamingMapping::new(mapping_id, buffer_va, dma_addr, size, direction, bounce_buffer);
        self.streaming_mappings.insert(mapping_id, mapping);
        stats.record_streaming_map();
        Ok(mapping_id)
    }

    pub fn unmap_streaming(&mut self, mapping_id: u64, stats: &DmaStats) -> DmaResult<()> {
        let mapping =
            self.streaming_mappings.remove(&mapping_id).ok_or(DmaError::MappingNotFound)?;
        if let Some(bounce_region) = mapping.bounce_buffer {
            if mapping.direction.reads_from_device() {
                self.copy_buffer(bounce_region.virt_addr, mapping.buffer_va, mapping.size)?;
            }
            self.free_coherent(bounce_region.virt_addr, stats)?;
            stats.record_bounce_usage(false);
        }
        stats.record_streaming_unmap();
        Ok(())
    }

    pub fn sync_for_device(&self, mapping_id: u64) -> DmaResult<()> {
        let mapping = self.streaming_mappings.get(&mapping_id).ok_or(DmaError::MappingNotFound)?;
        if let Some(bounce_region) = mapping.bounce_buffer {
            if mapping.direction.writes_to_device() {
                self.copy_buffer(mapping.buffer_va, bounce_region.virt_addr, mapping.size)?;
            }
        }
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    pub fn sync_for_cpu(&self, mapping_id: u64) -> DmaResult<()> {
        compiler_fence(Ordering::SeqCst);
        let mapping = self.streaming_mappings.get(&mapping_id).ok_or(DmaError::MappingNotFound)?;
        if let Some(bounce_region) = mapping.bounce_buffer {
            if mapping.direction.reads_from_device() {
                self.copy_buffer(bounce_region.virt_addr, mapping.buffer_va, mapping.size)?;
            }
        }
        Ok(())
    }
}
