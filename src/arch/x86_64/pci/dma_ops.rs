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
use super::stats::{DMA_BYTES_COUNTER, DMA_TRANSFER_COUNTER, PCI_STATS};
use core::sync::atomic::Ordering;

pub fn sync_buffer_for_device(buffer: &DmaBuffer) {
    if buffer.coherent {
        return;
    }
    let start = buffer.virt_addr.as_u64() as usize;
    for addr in (start..start + buffer.size).step_by(64) {
        io::clflush(addr);
    }
    io::mfence();
}

pub fn sync_buffer_for_cpu(buffer: &DmaBuffer) {
    sync_buffer_for_device(buffer);
}

pub fn do_transfer(
    engine: &mut DmaEngine,
    direction: DmaDirection,
    buffer: &DmaBuffer,
    transfers: &mut u64,
    bytes: &mut u64,
) -> PciResult<()> {
    *transfers += 1;
    *bytes += buffer.size as u64;
    DMA_TRANSFER_COUNTER.fetch_add(1, Ordering::Relaxed);
    DMA_BYTES_COUNTER.fetch_add(buffer.size as u64, Ordering::Relaxed);
    match direction {
        DmaDirection::ToDevice | DmaDirection::Bidirectional => sync_buffer_for_device(buffer),
        DmaDirection::FromDevice => sync_buffer_for_cpu(buffer),
    }
    Ok(())
}

pub fn free_buffers(buffers: &mut alloc::vec::Vec<DmaBuffer>) {
    for buf in buffers.drain(..) {
        let _ = crate::memory::dma::free_dma_buffer(buf.phys_addr, buf.size);
    }
}

pub fn cleanup_engine(dma_engines_delta: i32) {
    let mut stats = PCI_STATS.write();
    if dma_engines_delta < 0 {
        stats.dma_engines = stats.dma_engines.saturating_sub((-dma_engines_delta) as u64);
    }
}
