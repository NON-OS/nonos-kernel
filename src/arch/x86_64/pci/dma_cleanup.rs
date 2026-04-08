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

use super::device::PciDevice;
use super::dma_engine::DmaEngine;
use super::stats::PCI_STATS;

impl DmaEngine {
    pub fn free_all(&mut self) {
        for buffer in self.coherent_buffers.drain(..) {
            let _ = crate::memory::dma::free_dma_buffer(buffer.phys_addr, buffer.size);
        }
        for buffer in self.streaming_buffers.drain(..) {
            let _ = crate::memory::dma::free_dma_buffer(buffer.phys_addr, buffer.size);
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.total_transfers, self.total_bytes)
    }

    pub fn device(&self) -> &PciDevice {
        &self.device
    }
}

impl Drop for DmaEngine {
    fn drop(&mut self) {
        self.free_all();
        let mut stats = PCI_STATS.write();
        stats.dma_engines = stats.dma_engines.saturating_sub(1);
    }
}
