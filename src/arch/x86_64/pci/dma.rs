// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use x86_64::{PhysAddr, VirtAddr};

use super::device::PciDevice;
use super::error::{PciError, PciResult};
use super::io;
use super::stats::{DMA_BYTES_COUNTER, DMA_TRANSFER_COUNTER, PCI_STATS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    ToDevice,
    FromDevice,
    Bidirectional,
}

pub struct DmaBuffer {
    pub virt_addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
    pub coherent: bool,
}

#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct DmaDescriptor {
    pub addr: u64,
    pub length: u32,
    pub flags: u32,
}

impl DmaDescriptor {
    pub const FLAG_EOC: u32 = 0x8000_0000;
    pub const FLAG_IOC: u32 = 0x4000_0000;

    pub const fn new(addr: u64, length: u32, flags: u32) -> Self {
        Self { addr, length, flags }
    }

    pub fn set_end_of_chain(&mut self) {
        self.flags |= Self::FLAG_EOC;
    }

    pub fn set_interrupt(&mut self) {
        self.flags |= Self::FLAG_IOC;
    }
}

pub struct DmaEngine {
    device: PciDevice,
    coherent_buffers: Vec<DmaBuffer>,
    streaming_buffers: Vec<DmaBuffer>,
    total_transfers: u64,
    total_bytes: u64,
}

impl DmaEngine {
    pub fn new(device: PciDevice) -> PciResult<Self> {
        device.enable_bus_mastering()?;
        device.enable_memory_space()?;

        {
            let mut stats = PCI_STATS.write();
            stats.dma_engines += 1;
        }

        Ok(DmaEngine {
            device,
            coherent_buffers: Vec::new(),
            streaming_buffers: Vec::new(),
            total_transfers: 0,
            total_bytes: 0,
        })
    }

    pub fn alloc_coherent(&mut self, size: usize) -> PciResult<&DmaBuffer> {
        let phys_addr = crate::memory::dma::allocate_dma_buffer(size)
            .map_err(|_| PciError::DmaAllocationFailed { size })?;
        let virt_addr = crate::memory::phys_to_virt(phys_addr);

        let buffer = DmaBuffer { virt_addr, phys_addr, size, coherent: true };
        self.coherent_buffers.push(buffer);
        Ok(self.coherent_buffers.last().unwrap())
    }

    pub fn alloc_streaming(&mut self, size: usize) -> PciResult<&DmaBuffer> {
        let phys_addr = crate::memory::dma::allocate_dma_buffer(size)
            .map_err(|_| PciError::DmaAllocationFailed { size })?;
        let virt_addr = crate::memory::phys_to_virt(phys_addr);

        let buffer = DmaBuffer { virt_addr, phys_addr, size, coherent: false };
        self.streaming_buffers.push(buffer);
        Ok(self.streaming_buffers.last().unwrap())
    }

    pub fn sync_for_device(&self, buffer: &DmaBuffer) {
        if buffer.coherent {
            return;
        }

        let start = buffer.virt_addr.as_u64() as usize;
        let end = start + buffer.size;

        for addr in (start..end).step_by(64) {
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
            DmaDirection::ToDevice => self.sync_for_device(buffer),
            DmaDirection::FromDevice => self.sync_for_cpu(buffer),
            DmaDirection::Bidirectional => self.sync_for_device(buffer),
        }

        Ok(())
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dma_descriptor() {
        let mut desc = DmaDescriptor::new(0x1000, 4096, 0);
        assert_eq!(desc.addr, 0x1000);
        assert_eq!(desc.length, 4096);
        assert_eq!(desc.flags, 0);

        desc.set_end_of_chain();
        assert_eq!(desc.flags & DmaDescriptor::FLAG_EOC, DmaDescriptor::FLAG_EOC);

        desc.set_interrupt();
        assert_eq!(desc.flags & DmaDescriptor::FLAG_IOC, DmaDescriptor::FLAG_IOC);
    }
}
