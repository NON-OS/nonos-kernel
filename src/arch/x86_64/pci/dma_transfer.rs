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

use super::dma_engine::DmaEngine;
use super::dma_types::{DmaBuffer, DmaDirection};
use super::error::PciResult;
use super::io;
use super::stats::{DMA_BYTES_COUNTER, DMA_TRANSFER_COUNTER};
use core::sync::atomic::Ordering;

impl DmaEngine {
    pub fn sync_for_device(&self, buffer: &DmaBuffer) {
        if buffer.coherent {
            return;
        }
        let start = buffer.virt_addr.as_u64() as usize;
        for addr in (start..start + buffer.size).step_by(64) {
            io::clflush(addr);
        }
        io::mfence();
    }

    pub fn sync_for_cpu(&self, buffer: &DmaBuffer) {
        self.sync_for_device(buffer);
    }

    pub fn transfer(&mut self, direction: DmaDirection, buffer: &DmaBuffer) -> PciResult<()> {
        self.total_transfers += 1;
        self.total_bytes += buffer.size as u64;
        DMA_TRANSFER_COUNTER.fetch_add(1, Ordering::Relaxed);
        DMA_BYTES_COUNTER.fetch_add(buffer.size as u64, Ordering::Relaxed);
        match direction {
            DmaDirection::ToDevice | DmaDirection::Bidirectional => self.sync_for_device(buffer),
            DmaDirection::FromDevice => self.sync_for_cpu(buffer),
        }
        Ok(())
    }
}
